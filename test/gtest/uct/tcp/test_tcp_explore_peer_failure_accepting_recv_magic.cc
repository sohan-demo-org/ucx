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
}

#include <dirent.h>


/**
 * Peer failure while an EP is in a handshake state (RECV_MAGIC_NUMBER /
 * ACCEPTING), with and without UCX_TCP_CONN_TIMEOUT armed. The peers are raw
 * sockets which send (part of) the magic number and then close or reset the
 * connection before CONN_REQ. The checks only use fields which exist on
 * master as well, so the tests compile with and without the timeout patch;
 * the timeout-specific parts skip when TCP_CONN_TIMEOUT is not a config knob.
 */
class test_uct_tcp_explore_pf_accepting : public uct_test {
public:
    test_uct_tcp_explore_pf_accepting() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_have_timeout(false)
    {
    }

    void init()
    {
        std::string value;

        uct_test::init();
        /* config field name without the UCX_TCP_ prefix */
        m_have_timeout = get_config("CONN_TIMEOUT", value);
        if (m_have_timeout) {
            modify_config("TCP_CONN_TIMEOUT", conn_timeout_str(),
                          IGNORE_IF_NOT_EXIST);
        }

        m_ent = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_ent);
        m_tcp_iface = ucs_derived_of(m_ent->iface(), uct_tcp_iface_t);
    }

    void cleanup()
    {
        close_fds(m_raw_fds);
        uct_test::cleanup();
    }

protected:
    static const double CONN_TIMEOUT_SEC;
    static const double WAIT_TIMEOUT_SEC;

    static std::string conn_timeout_str()
    {
        return ucs::to_string((unsigned)(CONN_TIMEOUT_SEC * 1000)) + "ms";
    }

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_pf_accepting *self =
                reinterpret_cast<test_uct_tcp_explore_pf_accepting*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_eps.push_back(ep);
        return UCS_OK;
    }

    static void close_fds(std::vector<int> &fds)
    {
        for (size_t i = 0; i < fds.size(); ++i) {
            close(fds[i]);
        }
        fds.clear();
    }

    /* Close one raw fd; with @a reset the peer sees RST instead of FIN */
    void close_raw_fd(int fd, bool reset)
    {
        if (reset) {
            struct linger l = {1, 0};
            EXPECT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)));
        }

        close(fd);
        m_raw_fds.erase(std::remove(m_raw_fds.begin(), m_raw_fds.end(), fd),
                        m_raw_fds.end());
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

    /* Listening socket on the iface IP address which never accepts the
     * connection and never speaks the UCT TCP protocol */
    int raw_listener(struct sockaddr_storage *addr, int backlog = 16)
    {
        socklen_t addr_len;
        size_t addr_size;
        int fd;

        memcpy(addr, iface_addr(), sizeof(*addr));
        ASSERT_UCS_OK(ucs_sockaddr_set_port((struct sockaddr*)addr, 0));
        ASSERT_UCS_OK(ucs_sockaddr_sizeof((struct sockaddr*)addr, &addr_size));
        ASSERT_UCS_OK(ucs_socket_create(addr->ss_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);

        EXPECT_EQ(0, bind(fd, (struct sockaddr*)addr, addr_size));
        EXPECT_EQ(0, listen(fd, backlog));
        ASSERT_UCS_OK(ucs_socket_getname(fd, addr, &addr_len));
        return fd;
    }

    /* Raw listener whose address is lower than the iface address, so that
     * the local side is the accepting one for CONNECT_TO_EP connections.
     * Returns false if no such port could be obtained. */
    bool lower_raw_listener(struct sockaddr_storage *addr)
    {
        ucs_status_t status;
        int cmp = 1;

        for (int i = 0; (i < 64) && (cmp >= 0); ++i) {
            raw_listener(addr);
            cmp = ucs_sockaddr_cmp((struct sockaddr*)addr, iface_addr(),
                                   &status);
            EXPECT_UCS_OK(status);
        }

        return cmp < 0;
    }

    /* Non-blocking raw socket connected (or connecting) to @a addr */
    int raw_connect(const struct sockaddr *addr)
    {
        int fd;

        ASSERT_UCS_OK(ucs_socket_create(addr->sa_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);
        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));

        ucs_status_t status = ucs_socket_connect(fd, addr);
        EXPECT_TRUE((status == UCS_OK) || (status == UCS_INPROGRESS));
        return fd;
    }

    /* Raw client connected to the iface listener which has sent the first
     * @a magic_bytes bytes of the magic number */
    int raw_client_send_magic(size_t magic_bytes)
    {
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;
        int fd         = raw_connect(iface_addr());

        while (!ucs_socket_is_connected(fd)) {
            progress();
        }

        ASSERT_UCS_OK(ucs_socket_send(fd, &magic, magic_bytes));
        return fd;
    }

    /* Peer address "below" the iface address so that the CONN_REQ is for a
     * connection the local side has to accept */
    void send_conn_req(int fd, ucs_ptr_map_key_t ptr_map_key,
                       const struct sockaddr *peer_addr)
    {
        size_t sockaddr_len = m_tcp_iface->config.sockaddr_len;
        std::vector<uint8_t> buf(sizeof(uct_tcp_am_hdr_t) +
                                 sizeof(uct_tcp_cm_conn_req_pkt_t) +
                                 sockaddr_len);
        uct_tcp_am_hdr_t *hdr = (uct_tcp_am_hdr_t*)&buf[0];
        uct_tcp_cm_conn_req_pkt_t *pkt = (uct_tcp_cm_conn_req_pkt_t*)(hdr + 1);

        hdr->am_id           = UCT_TCP_EP_CM_AM_ID;
        hdr->length          = sizeof(*pkt) + sockaddr_len;
        pkt->event           = UCT_TCP_CM_CONN_REQ;
        pkt->flags           = UCT_TCP_CM_CONN_REQ_PKT_FLAG_CONNECT_TO_EP;
        pkt->cm_id.conn_sn   = 0;
        pkt->cm_id.ptr_map_key = ptr_map_key;
        memcpy(pkt + 1, peer_addr, sockaddr_len);

        ASSERT_UCS_OK(ucs_socket_send(fd, &buf[0], buf.size()));
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

    /* CONNECT_TO_EP EP for which the local side is the accepting one: it
     * ends up in ACCEPTING with fd == -1 waiting for CONN_REQ from a peer at
     * @a peer_addr (a raw listener which never sends anything). Returns the
     * ptr map key a peer would put into its CONN_REQ. */
    uct_ep_h create_accepting_c2e_ep(const struct sockaddr *peer_addr,
                                     ucs_ptr_map_key_t *ptr_map_key_p)
    {
        std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
        std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
        uct_tcp_ep_addr_t *remote_addr = (uct_tcp_ep_addr_t*)&ep_addr[0];
        uct_ep_connect_to_ep_params_t conn_params = {0};
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = m_ent->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        ASSERT_UCS_OK(uct_ep_get_address(ep, (uct_ep_addr_t*)&ep_addr[0]));
        *ptr_map_key_p = remote_addr->ptr_map_key;

        ASSERT_UCS_OK(uct_iface_get_device_address(
                m_ent->iface(), (uct_device_addr_t*)&dev_addr[0]));
        remote_addr->iface_addr.port = htons(port_of(peer_addr));
        remote_addr->ptr_map_key     = 0x1234; /* peer's key, never used */

        ASSERT_UCS_OK(uct_ep_connect_to_ep_v2(ep,
                                              (uct_device_addr_t*)&dev_addr[0],
                                              (uct_ep_addr_t*)&ep_addr[0],
                                              &conn_params));
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
        EXPECT_EQ(-1, tcp_ep(ep)->fd);
        EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
        EXPECT_TRUE(ptr_map_has(*ptr_map_key_p));
        return ep;
    }

    bool ptr_map_has(ucs_ptr_map_key_t key)
    {
        void *ptr;
        return UCS_PTR_MAP_GET(tcp_ep, &m_tcp_iface->ep_ptr_map, key, 0,
                               &ptr) == UCS_OK;
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

    /* Number of EPs on the iface EP list (internal EPs and user EPs which
     * are not on the connection matching context) */
    size_t ep_count()
    {
        size_t num = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(m_tcp_iface->super.worker->async);
        ucs_list_for_each(ep, &m_tcp_iface->ep_list, list) {
            ++num;
        }
        UCS_ASYNC_UNBLOCK(m_tcp_iface->super.worker->async);
        return num;
    }

    size_t ep_count_in_state(uct_tcp_ep_conn_state_t state)
    {
        size_t num = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(m_tcp_iface->super.worker->async);
        ucs_list_for_each(ep, &m_tcp_iface->ep_list, list) {
            num += (ep->conn_state == state);
        }
        UCS_ASYNC_UNBLOCK(m_tcp_iface->super.worker->async);
        return num;
    }

    /* Returns the rx length of the single internal EP in RECV_MAGIC_NUMBER,
     * or -1 if there is no such EP */
    ssize_t magic_rx_length()
    {
        ssize_t length = -1;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(m_tcp_iface->super.worker->async);
        ucs_list_for_each(ep, &m_tcp_iface->ep_list, list) {
            if (ep->conn_state == UCT_TCP_EP_CONN_STATE_RECV_MAGIC_NUMBER) {
                length = ep->rx.length;
            }
        }
        UCS_ASYNC_UNBLOCK(m_tcp_iface->super.worker->async);
        return length;
    }

    void wait_for_ep_count(size_t count)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((ep_count() != count) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_EQ(count, ep_count());
    }

    void wait_for_ep_count_in_state(uct_tcp_ep_conn_state_t state,
                                    size_t count)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((ep_count_in_state(state) != count) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
        ASSERT_EQ(count, ep_count_in_state(state));
    }

    /* Wait until the single magic-receiving internal EP has read exactly
     * @a length bytes of the magic number */
    void wait_for_magic_rx_length(size_t length)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((magic_rx_length() != (ssize_t)length) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
        ASSERT_EQ((ssize_t)length, magic_rx_length());
    }

    /* Raw client connected to the iface whose internal EP is in ACCEPTING:
     * magic received, CONN_REQ never sent. @a outstanding_before is the
     * iface outstanding count before this client */
    int raw_client_in_accepting(size_t outstanding_before)
    {
        size_t accepting_before =
                ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING);
        int fd = raw_client_send_magic(sizeof(uint64_t));

        wait_for_ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING,
                                   accepting_before + 1);
        EXPECT_EQ(outstanding_before + 1, m_tcp_iface->outstanding);
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));
        return fd;
    }

    /* The peer must have been reset by the iface closing the accepted
     * socket (the EP was destroyed): recv returns an error, not EAGAIN */
    void expect_peer_sees_close(int fd)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        ucs_status_t status;
        uint8_t byte;
        size_t len;

        do {
            scoped_log_handler slh(wrap_errors_logger);
            len    = sizeof(byte);
            status = ucs_socket_recv_nb(fd, &byte, 0, &len);
        } while ((status == UCS_ERR_NO_PROGRESS) &&
                 (ucs_get_time() < deadline));
        EXPECT_NE(UCS_OK, status);
        EXPECT_NE(UCS_ERR_NO_PROGRESS, status);
    }

    /* Invariants once a user EP was failed by the connection timeout */
    void check_timed_out_ep(uct_ep_h ep)
    {
        ASSERT_EQ(1u, m_err_count);
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
        EXPECT_EQ(ep, m_err_eps[0]);
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    }

    void skip_without_timeout()
    {
        if (!m_have_timeout) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a config knob");
        }
    }

    /* Internal EP created for a raw client which is reset by the peer in
     * @a state (RECV_MAGIC_NUMBER with a partial magic, ACCEPTING with the
     * full magic). @a armed_ep is an optional user EP which is stuck in a
     * handshake state and has the connection timeout armed. */
    void peer_failure_internal_ep(uct_tcp_ep_conn_state_t state, bool reset,
                                  uct_ep_h armed_ep)
    {
        size_t outstanding_before = m_tcp_iface->outstanding;
        size_t ep_count_before    = ep_count();
        size_t fd_count           = open_fd_count();
        int fd;

        if (state == UCT_TCP_EP_CONN_STATE_ACCEPTING) {
            fd = raw_client_in_accepting(outstanding_before);
        } else {
            ASSERT_EQ(UCT_TCP_EP_CONN_STATE_RECV_MAGIC_NUMBER, state);
            fd = raw_client_send_magic(sizeof(uint64_t) / 2);
            wait_for_magic_rx_length(sizeof(uint64_t) / 2);
            /* RECV_MAGIC_NUMBER does not hold a unit of outstanding */
            EXPECT_EQ(outstanding_before, m_tcp_iface->outstanding);
        }
        ASSERT_EQ(ep_count_before + 1, ep_count());

        close_raw_fd(fd, reset);

        /* The internal EP has to be destroyed by the deferred one-shot: no
         * user EP, so no error callback */
        wait_for_ep_count(ep_count_before);
        EXPECT_EQ(0u, ep_count_in_state(state));
        EXPECT_EQ(0u, m_err_count);
        EXPECT_EQ(outstanding_before, m_tcp_iface->outstanding);
        EXPECT_EQ(fd_count, open_fd_count());

        if (armed_ep != NULL) {
            /* the stalled user EP is untouched by the internal EP failure */
            EXPECT_TRUE((conn_state(armed_ep) ==
                         UCT_TCP_EP_CONN_STATE_CONNECTING) ||
                        (conn_state(armed_ep) ==
                         UCT_TCP_EP_CONN_STATE_WAITING_ACK));
            EXPECT_EQ(1u, m_tcp_iface->outstanding);
            EXPECT_EQ(UCS_INPROGRESS,
                      uct_iface_flush(m_ent->iface(), 0, NULL));
        } else {
            EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
        }
    }

    uct_tcp_iface_t       *m_tcp_iface;
    entity                *m_ent;
    unsigned              m_err_count;
    ucs_status_t          m_err_status;
    bool                  m_have_timeout;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<int>      m_raw_fds;
};

const double test_uct_tcp_explore_pf_accepting::CONN_TIMEOUT_SEC = 1.0;
const double test_uct_tcp_explore_pf_accepting::WAIT_TIMEOUT_SEC = 10.0;


/* Peer sends the magic number (internal EP -> ACCEPTING, outstanding 1) and
 * then closes the socket before CONN_REQ: ACCEPTING -> set_failed(RESET) ->
 * deferred destroy -> CLOSED. Runs with the default (infinite) timeout, so
 * identical on master and on the PR. */
UCS_TEST_P(test_uct_tcp_explore_pf_accepting, accepting_peer_close)
{
    peer_failure_internal_ep(UCT_TCP_EP_CONN_STATE_ACCEPTING, false, NULL);
}

/* Same with RST instead of FIN */
UCS_TEST_P(test_uct_tcp_explore_pf_accepting, accepting_peer_rst)
{
    peer_failure_internal_ep(UCT_TCP_EP_CONN_STATE_ACCEPTING, true, NULL);
}

/* Peer closes after half of the magic number (RECV_MAGIC_NUMBER, no
 * outstanding): deferred destroy as well */
UCS_TEST_P(test_uct_tcp_explore_pf_accepting, recv_magic_peer_close)
{
    peer_failure_internal_ep(UCT_TCP_EP_CONN_STATE_RECV_MAGIC_NUMBER, false,
                             NULL);
}

/* Internal EP is reset in ACCEPTING / RECV_MAGIC_NUMBER while the connection
 * timeout is armed on it (ACCEPTING) and on another user EP stuck in
 * WAITING_ACK. The internal EP must be destroyed right away by the peer
 * failure and leave the timeout list; the user EP must still be reported
 * exactly once by the timeout afterwards (a stale list entry would be a
 * use-after-free in the timeout sweep). */

UCS_TEST_P(test_uct_tcp_explore_pf_accepting, accepting_peer_rst_timeout_armed)
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;

    skip_without_timeout();

    raw_listener(&listen_addr);
    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
    ASSERT_EQ(1u, m_tcp_iface->outstanding);

    peer_failure_internal_ep(UCT_TCP_EP_CONN_STATE_ACCEPTING, true, ep);
    peer_failure_internal_ep(UCT_TCP_EP_CONN_STATE_RECV_MAGIC_NUMBER, false,
                             ep);

    /* The user EP times out once; the destroyed internal EPs are not on the
     * timeout list anymore */
    wait_for_err();
    check_timed_out_ep(ep);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* CONNECT_TO_EP accept side: the user EP waits in ACCEPTING (fd == -1) for
 * CONN_REQ. The peer's connection (internal EP) is reset after the magic:
 * the internal EP is destroyed on its own, the user EP stays in ACCEPTING
 * and is not reported (no timeout) - only uct_ep_destroy() frees it. A late
 * CONN_REQ with its ptr map key after the destroy is dropped. */
UCS_TEST_P(test_uct_tcp_explore_pf_accepting, c2e_accepting_peer_internal_reset)
{
    struct sockaddr_storage listen_addr;
    ucs_ptr_map_key_t ptr_map_key;
    size_t fd_count;
    uct_ep_h ep;
    int fd;

    if (m_have_timeout) {
        /* behaviour without the timeout: use the default */
        modify_config("TCP_CONN_TIMEOUT", "inf", IGNORE_IF_NOT_EXIST);
        m_entities.clear();
        m_ent       = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_ent);
        m_tcp_iface = ucs_derived_of(m_ent->iface(), uct_tcp_iface_t);
    }

    fd_count = open_fd_count();
    if (!lower_raw_listener(&listen_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    ep       = create_accepting_c2e_ep((struct sockaddr*)&listen_addr,
                                       &ptr_map_key);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    /* peer connects, sends the magic and resets: only the internal EP goes */
    fd = raw_client_in_accepting(1);
    EXPECT_EQ(2u, ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING));
    close_raw_fd(fd, true);
    wait_for_ep_count(1);

    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_TRUE(ptr_map_has(ptr_map_key));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));

    /* ACCEPTING -> CLOSED by the user destroying the EP */
    uct_ep_destroy(ep);
    EXPECT_FALSE(ptr_map_has(ptr_map_key));
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    /* late CONN_REQ for the destroyed EP: internal EP dropped */
    fd = raw_client_in_accepting(0);
    send_conn_req(fd, ptr_map_key, (struct sockaddr*)&listen_addr);
    wait_for_ep_count(0);
    expect_peer_sees_close(fd);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* CONNECT_TO_EP accept side with the timeout armed: the peer's internal EP
 * is reset after the magic and destroyed independently; the user EP can
 * only be failed by the timeout: ENDPOINT_TIMEOUT exactly once, off the ptr
 * map, outstanding 0. A CONN_REQ arriving after that is dropped and can't
 * revive the EP. */
UCS_TEST_P(test_uct_tcp_explore_pf_accepting,
           c2e_accepting_timeout_after_peer_reset)
{
    struct sockaddr_storage listen_addr;
    ucs_ptr_map_key_t ptr_map_key;
    size_t fd_count;
    uct_ep_h ep;
    int fd;

    skip_without_timeout();

    fd_count = open_fd_count();
    if (!lower_raw_listener(&listen_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    ep       = create_accepting_c2e_ep((struct sockaddr*)&listen_addr,
                                       &ptr_map_key);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    fd = raw_client_in_accepting(1);
    close_raw_fd(fd, true);
    wait_for_ep_count(1);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    wait_for_err();
    check_timed_out_ep(ep);
    EXPECT_FALSE(ptr_map_has(ptr_map_key));
    EXPECT_EQ(1u, ep_count());
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    /* late CONN_REQ: the failed EP must not become CONNECTED */
    fd = raw_client_in_accepting(0);
    send_conn_req(fd, ptr_map_key, (struct sockaddr*)&listen_addr);
    wait_for_ep_count(1);
    expect_peer_sees_close(fd);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(-1, tcp_ep(ep)->fd);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);

    uct_ep_destroy(ep);
    EXPECT_EQ(0u, ep_count());
    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* Destroy a CONNECT_TO_EP user EP while it is ACCEPTING with the timeout
 * armed, before the deadline: outstanding 0, ptr map entry gone, and the
 * timeout sweep must not touch the destroyed EP afterwards */
UCS_TEST_P(test_uct_tcp_explore_pf_accepting, c2e_destroy_while_accepting_armed)
{
    struct sockaddr_storage listen_addr;
    ucs_ptr_map_key_t ptr_map_key;
    size_t fd_count;
    uct_ep_h ep;
    int fd;

    skip_without_timeout();

    fd_count = open_fd_count();
    if (!lower_raw_listener(&listen_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    ep       = create_accepting_c2e_ep((struct sockaddr*)&listen_addr,
                                       &ptr_map_key);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    uct_ep_destroy(ep);
    EXPECT_FALSE(ptr_map_has(ptr_map_key));
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    /* past the deadline: nothing to time out */
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    /* late CONN_REQ for the destroyed EP: internal EP dropped */
    fd = raw_client_in_accepting(0);
    send_conn_req(fd, ptr_map_key, (struct sockaddr*)&listen_addr);
    wait_for_ep_count(0);
    expect_peer_sees_close(fd);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_pf_accepting, tcp)
