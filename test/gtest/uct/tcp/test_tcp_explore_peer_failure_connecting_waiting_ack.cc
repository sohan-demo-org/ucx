/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2025. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include <common/test.h>
#include <uct/uct_test.h>

extern "C" {
#include <uct/api/uct.h>
#include <uct/tcp/tcp.h>
#include <ucs/sys/sock.h>
#include <ucs/config/global_opts.h>
}

#include <dirent.h>


/**
 * Peer failure during the CONNECT_TO_IFACE handshake (CONNECTING and
 * WAITING_ACK), with and without UCX_TCP_CONN_TIMEOUT armed. The peers are
 * raw sockets fully controlled by the test, so every failure is injected
 * synchronously (connect refused on loopback, RST via SO_LINGER=0) and no
 * sleeps are needed for synchronisation.
 *
 * The file compiles on master as well: it only touches fields which exist
 * there. The connection timeout flag is probed through its bit value (see
 * EXPLORE_FLAG_CONN_TIMEOUT_ARMED).
 */
class test_uct_tcp_explore_peer_failure : public uct_test {
public:
    test_uct_tcp_explore_peer_failure() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_err_time(0), m_timeout_supported(false), m_timeout_armed(false)
    {
    }

    void init()
    {
        uct_test::init();

        /* the config exists only with the PR which adds it */
        std::string value;
        m_timeout_supported = get_config("CONN_TIMEOUT", value);
        if (conn_timeout_cfg() != NULL) {
            modify_config("TCP_CONN_TIMEOUT", conn_timeout_cfg(),
                          IGNORE_IF_NOT_EXIST);
            m_timeout_armed = m_timeout_supported;
        }

        m_ent = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_ent);
        m_tcp_iface = ucs_derived_of(m_ent->iface(), uct_tcp_iface_t);
    }

    void cleanup()
    {
        while (!m_raw_fds.empty()) {
            close_fd(m_raw_fds.back());
        }
        uct_test::cleanup();
    }

protected:
    /* UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED on the PR branch; master has no
     * flag at this bit, so it must always read as 0 there */
    static const uint16_t EXPLORE_FLAG_CONN_TIMEOUT_ARMED = UCS_BIT(11);
    static const double   CONN_TIMEOUT_SEC;
    static const double   WAIT_TIMEOUT_SEC;

    virtual const char *conn_timeout_cfg() const
    {
        return NULL;
    }

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_peer_failure *self =
                reinterpret_cast<test_uct_tcp_explore_peer_failure*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_time   = ucs_get_time();
        self->m_err_eps.push_back(ep);
        self->m_err_statuses.push_back(status);
        return UCS_OK;
    }

    static size_t open_fd_count()
    {
        DIR *dir = opendir("/proc/self/fd");
        size_t count = 0;

        EXPECT_TRUE(dir != NULL);
        while (readdir(dir) != NULL) {
            ++count;
        }
        closedir(dir);
        return count - 1; /* the directory stream itself */
    }

    const struct sockaddr *iface_addr() const
    {
        return (const struct sockaddr*)&m_tcp_iface->config.ifaddr;
    }

    void close_fd(int fd)
    {
        std::vector<int>::iterator it = std::find(m_raw_fds.begin(),
                                                 m_raw_fds.end(), fd);
        if (it != m_raw_fds.end()) {
            m_raw_fds.erase(it);
        }
        close(fd);
    }

    /* close() which sends RST instead of FIN */
    void reset_fd(int fd)
    {
        struct linger lg = {1, 0};

        EXPECT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)));
        close_fd(fd);
    }

    /* Non-blocking listening socket on the iface IP address which never
     * speaks the UCT TCP protocol by itself */
    int raw_listener(struct sockaddr_storage *addr)
    {
        socklen_t addr_len;
        size_t addr_size;
        int fd;

        memcpy(addr, iface_addr(), sizeof(*addr));
        ASSERT_UCS_OK(ucs_sockaddr_set_port((struct sockaddr*)addr, 0));
        ASSERT_UCS_OK(ucs_sockaddr_sizeof((struct sockaddr*)addr, &addr_size));
        ASSERT_UCS_OK(ucs_socket_create(addr->ss_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);
        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));

        EXPECT_EQ(0, bind(fd, (struct sockaddr*)addr, addr_size));
        EXPECT_EQ(0, listen(fd, 16));
        ASSERT_UCS_OK(ucs_socket_getname(fd, addr, &addr_len));
        return fd;
    }

    /* Accept the connection the EP has established with the raw listener.
     * connect() is blocking on the EP side (TCP_CONN_NB=n), so the
     * connection is already in the accept queue when uct_ep_create()
     * returns; the loop only guards against a broken test */
    int raw_accept(int listen_fd)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        int fd;

        do {
            fd = accept(listen_fd, NULL, NULL);
            if (fd >= 0) {
                m_raw_fds.push_back(fd);
                EXPECT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));
                return fd;
            }
            EXPECT_TRUE((errno == EAGAIN) || (errno == EWOULDBLOCK));
            progress();
        } while (ucs_get_time() < deadline);

        ADD_FAILURE() << "no connection accepted";
        return -1;
    }

    size_t conn_req_pkt_length() const
    {
        return sizeof(uint64_t) + sizeof(uct_tcp_am_hdr_t) +
               sizeof(uct_tcp_cm_conn_req_pkt_t) +
               m_tcp_iface->config.sockaddr_len;
    }

    /* Read the magic number + CONN_REQ sent by the EP on the accepted socket
     * and check it is what a CONNECTING EP sends */
    void recv_conn_req(int fd)
    {
        std::vector<uint8_t> buf(conn_req_pkt_length());
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        size_t offset       = 0;
        ssize_t ret;

        while ((offset < buf.size()) && (ucs_get_time() < deadline)) {
            ret = recv(fd, &buf[offset], buf.size() - offset, MSG_DONTWAIT);
            if (ret > 0) {
                offset += ret;
            } else {
                ASSERT_TRUE((ret < 0) && ((errno == EAGAIN) ||
                                          (errno == EWOULDBLOCK)))
                        << "recv returned " << ret << " errno " << errno;
                progress();
            }
        }
        ASSERT_EQ(buf.size(), offset) << "CONN_REQ not received";

        const uct_tcp_am_hdr_t *hdr =
                (const uct_tcp_am_hdr_t*)(&buf[0] + sizeof(uint64_t));
        const uct_tcp_cm_conn_req_pkt_t *req =
                (const uct_tcp_cm_conn_req_pkt_t*)(hdr + 1);

        EXPECT_EQ(UCT_TCP_MAGIC_NUMBER, *(const uint64_t*)&buf[0]);
        EXPECT_EQ(UCT_TCP_EP_CM_AM_ID, hdr->am_id);
        EXPECT_EQ(UCT_TCP_CM_CONN_REQ, req->event);
    }

    uint16_t port_of(const struct sockaddr *addr)
    {
        uint16_t port = 0;
        EXPECT_UCS_OK(ucs_sockaddr_get_port(addr, &port));
        return port;
    }

    /* CONNECT_TO_IFACE EP to a peer listening on @a port on the iface IP */
    uct_ep_h create_ep_to_port(uint16_t port)
    {
        std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;
        uct_ep_h ep;

        ASSERT_UCS_OK(uct_iface_get_device_address(
                m_ent->iface(), (uct_device_addr_t*)&dev_addr[0]));
        iface_addr.port   = htons(port);
        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = m_ent->iface();
        params.dev_addr   = (uct_device_addr_t*)&dev_addr[0];
        params.iface_addr = (uct_iface_addr_t*)&iface_addr;
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    void wait_for_err(unsigned count = 1)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((m_err_count < count) && (ucs_get_time() < deadline)) {
            progress();
        }
    }

    /* Progress for @a sec seconds, wall clock */
    void progress_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
            progress();
        }
    }

    void expect_armed(uct_ep_h ep, bool armed)
    {
        bool is_armed = tcp_ep(ep)->flags & EXPLORE_FLAG_CONN_TIMEOUT_ARMED;

        EXPECT_EQ(armed && m_timeout_armed, is_armed)
                << "ep flags 0x" << std::hex << tcp_ep(ep)->flags;
    }

    /* Invariants of an EP which is in the middle of the handshake: it holds
     * one unit of iface->outstanding (so the iface can't be flushed), it is
     * polled for RX, it is armed iff the timeout is configured */
    void check_in_progress_ep(uct_ep_h ep, uct_tcp_ep_conn_state_t state,
                              unsigned conn_retries)
    {
        EXPECT_EQ(state, conn_state(ep));
        EXPECT_EQ(conn_retries, tcp_ep(ep)->conn_retries);
        EXPECT_EQ(1u, m_tcp_iface->outstanding);
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));
        EXPECT_NE(-1, tcp_ep(ep)->fd);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_NE(0u, tcp_ep(ep)->events);
        expect_armed(ep, true);
        EXPECT_EQ(0u, m_err_count);
    }

    /* Invariants of an EP which has been reported as failed: the callback
     * fired exactly once with UCS_ERR_ENDPOINT_TIMEOUT, the EP is CLOSED and
     * not polled, it is disarmed, outstanding is back to zero, the iface
     * flushes, and extra progress (longer than the timeout) does not fire
     * the callback again */
    void check_failed_ep(uct_ep_h ep, unsigned conn_retries)
    {
        EXPECT_EQ(1u, m_err_count) << "error callback statuses: "
                                   << err_statuses_str();
        ASSERT_FALSE(m_err_eps.empty());
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_statuses[0]);
        EXPECT_EQ(ep, m_err_eps[0]);
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(conn_retries, tcp_ep(ep)->conn_retries);
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        expect_armed(ep, false);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

        progress_for(2 * CONN_TIMEOUT_SEC);
        EXPECT_EQ(1u, m_err_count) << "error callback statuses: "
                                   << err_statuses_str();
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
    }

    std::string err_statuses_str() const
    {
        std::stringstream ss;
        for (size_t i = 0; i < m_err_statuses.size(); ++i) {
            ss << (i ? ", " : "") << ucs_status_string(m_err_statuses[i]);
        }
        return ss.str();
    }

    void destroy_ep(uct_ep_h ep, size_t fd_count)
    {
        uct_ep_destroy(ep);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
        EXPECT_EQ(fd_count, open_fd_count());
    }

    /* EP connected to the raw listener, CONN_REQ consumed by the peer:
     * the EP is in WAITING_ACK with conn_retries == @a conn_retries */
    int accept_and_recv_conn_req(int listen_fd, uct_ep_h ep,
                                 unsigned conn_retries)
    {
        int fd = raw_accept(listen_fd);

        recv_conn_req(fd);
        check_in_progress_ep(ep, UCT_TCP_EP_CONN_STATE_WAITING_ACK,
                             conn_retries);
        return fd;
    }

    /* Progress until the EP has left WAITING_ACK (retry or failure) */
    void progress_until_reconnect(uct_ep_h ep)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);

        while ((tcp_ep(ep)->conn_retries == 1) && (m_err_count == 0) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
    }

    /* Scenario (a): the listener is gone before uct_ep_create(). With
     * TCP_CONN_NB=y the non-blocking connect() returns EINPROGRESS on
     * loopback and the refusal is seen by uct_tcp_cm_conn_progress() ->
     * uct_tcp_ep_set_failed(UCS_ERR_ENDPOINT_TIMEOUT). No retry. */
    void connect_refused()
    {
        struct sockaddr_storage listen_addr;
        int listen_fd = raw_listener(&listen_addr);
        uint16_t port = port_of((struct sockaddr*)&listen_addr);
        size_t fd_count;
        uct_ep_h ep;

        close_fd(listen_fd);
        fd_count = open_fd_count();

        {
            scoped_log_handler slh(wrap_errors_logger);
            ep = create_ep_to_port(port);
            check_in_progress_ep(ep, UCT_TCP_EP_CONN_STATE_CONNECTING, 1);
            wait_for_err();
            check_failed_ep(ep, 1);
        }

        destroy_ep(ep, fd_count);
    }

    /* Scenario (b): the peer accepts, consumes CONN_REQ and resets the
     * connection. The EP goes WAITING_ACK -> CLOSED -> CONNECTING ->
     * WAITING_ACK with conn_retries == 2, outstanding stays 1. A second
     * CONN_REQ arrives at the listener. With the timeout armed the EP must
     * be failed only after a full timeout counted from the retry. */
    void waiting_ack_reset_retry()
    {
        struct sockaddr_storage listen_addr;
        int listen_fd = raw_listener(&listen_addr);
        size_t fd_count = open_fd_count();
        uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
        int fd = accept_and_recv_conn_req(listen_fd, ep, 1);

        /* let a good part of the first deadline elapse so that a stale
         * deadline would be distinguishable from a fresh one */
        progress_for(CONN_TIMEOUT_SEC / 2);
        check_in_progress_ep(ep, UCT_TCP_EP_CONN_STATE_WAITING_ACK, 1);

        ucs_time_t reset_time = ucs_get_time();
        reset_fd(fd);
        progress_until_reconnect(ep);

        /* retry: CLOSED (outstanding-1, disarm) -> CONNECTING (outstanding+1,
         * fresh deadline) -> WAITING_ACK; the listener gets a new connection
         * with a new CONN_REQ */
        check_in_progress_ep(ep, UCT_TCP_EP_CONN_STATE_WAITING_ACK, 2);
        fd = accept_and_recv_conn_req(listen_fd, ep, 2);

        if (m_timeout_armed) {
            wait_for_err();
            check_failed_ep(ep, 2);
            /* the deadline was re-armed at the retry, not kept from the
             * first attempt */
            EXPECT_GE(m_err_time - reset_time,
                      ucs_time_from_sec(CONN_TIMEOUT_SEC));
        } else {
            /* master behaviour / timeout disabled: stuck forever */
            progress_for(2 * CONN_TIMEOUT_SEC);
            check_in_progress_ep(ep, UCT_TCP_EP_CONN_STATE_WAITING_ACK, 2);
        }

        close_fd(fd);
        destroy_ep(ep, fd_count);
    }

    /* Scenario (b) with TCP_MAX_CONN_RETRIES=1: the retry is rejected by
     * uct_tcp_cm_conn_start() (UCS_ERR_TIMED_OUT) and the
     * uct_tcp_ep_create_socket_and_connect() error path fails the EP */
    void waiting_ack_reset_max_retries()
    {
        struct sockaddr_storage listen_addr;
        int listen_fd = raw_listener(&listen_addr);
        size_t fd_count = open_fd_count();
        uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
        int fd = accept_and_recv_conn_req(listen_fd, ep, 1);

        {
            scoped_log_handler slh(wrap_errors_logger);
            reset_fd(fd);
            progress_until_reconnect(ep);
            check_failed_ep(ep, 2);
        }

        /* no new connection attempt reached the listener */
        EXPECT_EQ(-1, accept(listen_fd, NULL, NULL));
        EXPECT_TRUE((errno == EAGAIN) || (errno == EWOULDBLOCK));

        destroy_ep(ep, fd_count);
    }

    /* Scenario (b) where the listener is gone when the retry connects:
     * blocking connect() in uct_tcp_cm_conn_start() is refused after the EP
     * entered CONNECTING, so the error path must undo the CONNECTING
     * bookkeeping and report the EP exactly once */
    void waiting_ack_reset_then_refused()
    {
        struct sockaddr_storage listen_addr;
        int listen_fd = raw_listener(&listen_addr);
        size_t fd_count = open_fd_count();
        uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
        int fd = accept_and_recv_conn_req(listen_fd, ep, 1);

        {
            scoped_log_handler slh(wrap_errors_logger);
            close_fd(listen_fd);
            reset_fd(fd);
            progress_until_reconnect(ep);
            check_failed_ep(ep, 2);
        }

        destroy_ep(ep, fd_count - 1 /* listener */);
    }

    uct_tcp_iface_t       *m_tcp_iface;
    entity                *m_ent;
    unsigned              m_err_count;
    ucs_status_t          m_err_status;
    ucs_time_t            m_err_time;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<ucs_status_t> m_err_statuses;
    std::vector<int>      m_raw_fds;
    bool                  m_timeout_supported;
    bool                  m_timeout_armed;
};

const double test_uct_tcp_explore_peer_failure::CONN_TIMEOUT_SEC = 0.2;
const double test_uct_tcp_explore_peer_failure::WAIT_TIMEOUT_SEC = 10.0;


/* Timeout disabled (default): must behave exactly as master */
UCS_TEST_P(test_uct_tcp_explore_peer_failure, connect_refused, "TCP_CONN_NB=y")
{
    connect_refused();
}

UCS_TEST_P(test_uct_tcp_explore_peer_failure, waiting_ack_reset_retry)
{
    waiting_ack_reset_retry();
}

UCS_TEST_P(test_uct_tcp_explore_peer_failure, waiting_ack_reset_max_retries,
           "TCP_MAX_CONN_RETRIES=1")
{
    waiting_ack_reset_max_retries();
}

UCS_TEST_P(test_uct_tcp_explore_peer_failure, waiting_ack_reset_then_refused)
{
    waiting_ack_reset_then_refused();
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_peer_failure, tcp)


/* Same scenarios with UCX_TCP_CONN_TIMEOUT armed */
class test_uct_tcp_explore_peer_failure_timeout :
        public test_uct_tcp_explore_peer_failure {
public:
    void init()
    {
        test_uct_tcp_explore_peer_failure::init();
        if (!m_timeout_supported) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
        }
    }

protected:
    virtual const char *conn_timeout_cfg() const
    {
        return "200ms";
    }
};

UCS_TEST_P(test_uct_tcp_explore_peer_failure_timeout, connect_refused,
           "TCP_CONN_NB=y")
{
    connect_refused();
}

UCS_TEST_P(test_uct_tcp_explore_peer_failure_timeout, waiting_ack_reset_retry)
{
    waiting_ack_reset_retry();
}

UCS_TEST_P(test_uct_tcp_explore_peer_failure_timeout,
           waiting_ack_reset_max_retries, "TCP_MAX_CONN_RETRIES=1")
{
    waiting_ack_reset_max_retries();
}

UCS_TEST_P(test_uct_tcp_explore_peer_failure_timeout,
           waiting_ack_reset_then_refused)
{
    waiting_ack_reset_then_refused();
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_peer_failure_timeout, tcp)
