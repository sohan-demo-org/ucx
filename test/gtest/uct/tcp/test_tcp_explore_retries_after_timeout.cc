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
#include <sys/wait.h>
#include <poll.h>


/**
 * Exploration of connection retries combined with UCX_TCP_CONN_TIMEOUT:
 * - a flapping peer (accepts and immediately resets) makes the EP retry;
 *   every retry must re-arm the connection timeout, so the EP fails one
 *   conn_timeout after the LAST successful connect, never reconnects after the
 *   timeout and all iface invariants hold;
 * - TCP_MAX_CONN_RETRIES stops a flapping peer earlier through
 *   uct_tcp_ep_create_socket_and_connect()'s error path;
 * - uct_ep_connect_to_ep_v2() called on a CONNECT_TO_EP EP which left the EP
 *   PTR map: after a peer disconnect (the path the code was written for) and
 *   after a connection timeout.
 *
 * Peers are raw sockets controlled by the test, so there is no dependency on a
 * real UCT peer. The tests only use fields which exist with and without the
 * UCX_TCP_CONN_TIMEOUT change; timeout specific tests skip when the config is
 * not available.
 */
class test_uct_tcp_explore_retries_after_timeout :
        public ucs::clear_dontcopy_regions, public uct_test {
public:
    test_uct_tcp_explore_retries_after_timeout() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_err_time(0), m_has_conn_timeout(false)
    {
    }

    void init()
    {
        uct_test::init();

        char value[32];
        m_has_conn_timeout = (uct_config_get(m_iface_config, "CONN_TIMEOUT",
                                             value, sizeof(value)) == UCS_OK);
        if (m_has_conn_timeout) {
            /* Must be done before the iface is created */
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

    static const char *conn_timeout_str()
    {
        return "500ms";
    }

    void require_conn_timeout()
    {
        if (!m_has_conn_timeout) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
        }
    }

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_retries_after_timeout *self =
                reinterpret_cast<test_uct_tcp_explore_retries_after_timeout*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_time   = ucs_get_time();
        self->m_err_eps.push_back(ep);
        self->m_err_statuses.push_back(status);
        return UCS_OK;
    }

    static void close_fds(std::vector<int> &fds)
    {
        for (size_t i = 0; i < fds.size(); ++i) {
            close(fds[i]);
        }
        fds.clear();
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

    /* Non-blocking listening socket on the iface IP address; the test decides
     * when (and whether) to accept connections */
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
        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));
        ASSERT_UCS_OK(ucs_socket_getname(fd, addr, &addr_len));
        return fd;
    }

    /* Returns the accepted fd, or -1 if nothing is pending in the queue */
    int try_accept(int listen_fd)
    {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            EXPECT_TRUE((errno == EAGAIN) || (errno == EWOULDBLOCK))
                    << strerror(errno);
            return -1;
        }
        return fd;
    }

    /* Waits (progressing) until the peer connection shows up in the accept
     * queue of the raw listener */
    int accept_pending(int listen_fd)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        int fd;

        while (((fd = try_accept(listen_fd)) < 0) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_GE(fd, 0) << "no connection accepted from the EP";
        return fd;
    }

    /* Closes the accepted socket so that the peer gets RST */
    static void reset_fd(int fd)
    {
        struct linger l = {1, 0};
        EXPECT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)));
        close(fd);
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

    /* CONNECT_TO_EP EP, not connected yet (on the EP PTR map) */
    uct_ep_h create_ep_connect_to_ep(uct_tcp_ep_addr_t *ep_addr)
    {
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = m_ent->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        ASSERT_UCS_OK(uct_ep_get_address(ep, (uct_ep_addr_t*)ep_addr));
        EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
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

    static unsigned conn_retries(uct_ep_h ep)
    {
        return tcp_ep(ep)->conn_retries;
    }

    void wait_for_err(unsigned count = 1)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((m_err_count < count) && (ucs_get_time() < deadline)) {
            progress();
        }
    }

    void wait_for_retry(uct_ep_h ep, unsigned prev_retries)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((conn_retries(ep) == prev_retries) && (m_err_count == 0) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
    }

    void wait_for_state(uct_ep_h ep, uct_tcp_ep_conn_state_t state)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((conn_state(ep) != state) && (m_err_count == 0) &&
               (ucs_get_time() < deadline)) {
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

    /* Invariants of a user EP which was failed: CLOSED, no epoll interest,
     * no parked socket, the iface has nothing outstanding and can be flushed */
    void check_failed_ep_invariants(uct_ep_h ep)
    {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
        EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_MATCH_CTX);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    }

    /* Peer which accepts the EP connection and immediately resets it:
     * drives one retry of the EP. Returns the time at which the reset was
     * issued, i.e. a lower bound for the time of the re-armed deadline */
    ucs_time_t flap_once(int listen_fd, uct_ep_h ep)
    {
        unsigned retries = conn_retries(ep);
        int fd           = accept_pending(listen_fd);
        ucs_time_t now;

        now = ucs_get_time();
        reset_fd(fd);
        wait_for_retry(ep, retries);
        return now;
    }

    /* Runs uct_ep_connect_to_ep_v2() in a child process, so that a ucs_assert
     * failure (abort) is recorded instead of killing the test binary. Returns
     * the status (as a positive exit code: -status) or the fatal signal in
     * @a signal_p; the child's stderr is returned in @a output */
    ucs_status_t connect_to_ep_in_child(uct_ep_h ep,
                                        const uct_device_addr_t *dev_addr,
                                        const uct_ep_addr_t *ep_addr,
                                        int *signal_p, std::string &output)
    {
        uct_ep_connect_to_ep_params_t conn_params = {0};
        int pipefd[2];
        int status;
        char buf[1024];
        ssize_t nread;
        pid_t pid;

        output.clear();
        *signal_p = 0;
        EXPECT_EQ(0, pipe(pipefd));

        pid = fork();
        if (pid == 0) {
            /* child: no freeze/gdb on fatal errors, just abort() */
            ucs_global_opts.handle_errors = 0;
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[0]);
            close(pipefd[1]);
            ucs_status_t st = uct_ep_connect_to_ep_v2(ep, dev_addr, ep_addr,
                                                      &conn_params);
            _exit(-(int)st);
        }

        EXPECT_GT(pid, 0);
        close(pipefd[1]);
        while ((nread = read(pipefd[0], buf, sizeof(buf))) > 0) {
            output.append(buf, nread);
        }
        close(pipefd[0]);
        EXPECT_EQ(pid, waitpid(pid, &status, 0));

        if (WIFSIGNALED(status)) {
            *signal_p = WTERMSIG(status);
            return UCS_ERR_IO_ERROR;
        }

        EXPECT_TRUE(WIFEXITED(status));
        return (ucs_status_t)-WEXITSTATUS(status);
    }

    /* Find a raw listener whose address is lower than the iface address, so
     * that the local CONNECT_TO_EP EP is the accepting side */
    bool lower_raw_listener(struct sockaddr_storage *listen_addr)
    {
        ucs_status_t status;
        int cmp = 1;

        for (int i = 0; (i < 64) && (cmp >= 0); ++i) {
            raw_listener(listen_addr);
            cmp = ucs_sockaddr_cmp((struct sockaddr*)listen_addr, iface_addr(),
                                   &status);
            EXPECT_UCS_OK(status);
        }
        return cmp < 0;
    }

    uct_tcp_iface_t           *m_tcp_iface;
    entity                    *m_ent;
    unsigned                  m_err_count;
    ucs_status_t              m_err_status;
    ucs_time_t                m_err_time;
    bool                      m_has_conn_timeout;
    std::vector<uct_ep_h>     m_err_eps;
    std::vector<ucs_status_t> m_err_statuses;
    std::vector<int>          m_raw_fds;
};

const double test_uct_tcp_explore_retries_after_timeout::CONN_TIMEOUT_SEC = 0.5;
const double test_uct_tcp_explore_retries_after_timeout::WAIT_TIMEOUT_SEC = 10.0;


/* Flapping peer: accepted and reset 3 times, then accepted and stalled. Each
 * reset re-arms the deadline, so the EP must survive well past the first
 * deadline and fail one conn_timeout after the LAST reset; the failure must
 * not trigger another connection attempt.
 * Transitions: conn:CLOSED->CONNECTING_retry, tmo:rearm_retry,
 * retries:inc_conn_start */
UCS_TEST_P(test_uct_tcp_explore_retries_after_timeout, flapping_peer_rearms_deadline)
{
    const unsigned num_flaps = 3;
    struct sockaddr_storage listen_addr;
    ucs_time_t last_reset, start;
    size_t fd_count;
    int stall_fd;

    require_conn_timeout();

    int listen_fd = raw_listener(&listen_addr);
    fd_count      = open_fd_count();
    start         = ucs_get_time();
    uct_ep_h ep   = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));

    wait_for_state(ep, UCT_TCP_EP_CONN_STATE_WAITING_ACK);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, conn_retries(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    last_reset = start;
    for (unsigned i = 1; i <= num_flaps; ++i) {
        last_reset = flap_once(listen_fd, ep);

        ASSERT_EQ(0u, m_err_count) << "EP failed during flap " << i
                                   << " with " << ucs_status_string(m_err_status);
        EXPECT_EQ(i + 1, conn_retries(ep));
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
        EXPECT_NE(0u, tcp_ep(ep)->events);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_EQ(1u, m_tcp_iface->outstanding);
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

        /* Keep the EP waiting for 60% of the timeout before the next flap: by
         * the 2nd flap more than one conn_timeout passed since the first
         * connect, so a deadline which was not re-armed would have fired */
        progress_for(0.6 * CONN_TIMEOUT_SEC);
        ASSERT_EQ(0u, m_err_count) << "EP failed " << ucs_time_to_sec(
                ucs_get_time() - start) << " sec after creation, after flap "
                << i << ": the deadline was not re-armed by the retry";
    }

    EXPECT_GT(ucs_get_time() - start,
              ucs_time_from_sec(1.5 * CONN_TIMEOUT_SEC));

    /* The last connect is accepted but never answered */
    stall_fd = accept_pending(listen_fd);
    EXPECT_EQ(num_flaps + 1, conn_retries(ep));

    wait_for_err();
    ASSERT_EQ(1u, m_err_count);
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    EXPECT_EQ(ep, m_err_eps[0]);
    EXPECT_GE(m_err_time - last_reset, ucs_time_from_sec(CONN_TIMEOUT_SEC))
            << "EP failed " << ucs_time_to_sec(m_err_time - last_reset)
            << " sec after the last reset, timeout is " << CONN_TIMEOUT_SEC;
    EXPECT_EQ(num_flaps + 1, conn_retries(ep));
    check_failed_ep_invariants(ep);

    /* A timeout must not cause a reconnect: nothing new in the accept queue,
     * no new attempt counted, the error is not reported again */
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(-1, try_accept(listen_fd)) << "EP reconnected after timeout";
    EXPECT_EQ(num_flaps + 1, conn_retries(ep));
    EXPECT_EQ(1u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));

    uct_ep_destroy(ep);
    close(stall_fd);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* TCP_MAX_CONN_RETRIES=2 with a flapping peer: the 1st reset is retried
 * (conn_retries 1 -> 2), the 2nd reset exceeds the maximum in
 * uct_tcp_cm_conn_start() and uct_tcp_ep_create_socket_and_connect() fails
 * the EP. The error must be reported exactly once, nothing reconnects, no fd
 * leaks. Runs with and without the timeout change.
 * Transitions: retries:exceed_max, conn:CLOSED->CONNECTING_retry */
UCS_TEST_P(test_uct_tcp_explore_retries_after_timeout, max_conn_retries_flapping,
           "TCP_MAX_CONN_RETRIES=2")
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;
    int fd;

    int listen_fd = raw_listener(&listen_addr);
    fd_count      = open_fd_count();
    uct_ep_h ep   = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));

    wait_for_state(ep, UCT_TCP_EP_CONN_STATE_WAITING_ACK);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, conn_retries(ep));

    flap_once(listen_fd, ep);
    ASSERT_EQ(0u, m_err_count);
    EXPECT_EQ(2u, conn_retries(ep));
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    {
        /* "reached maximum number of connection retries" and the somaxconn
         * hint are logged as errors */
        scoped_log_handler slh(wrap_errors_logger);
        fd = accept_pending(listen_fd);
        reset_fd(fd);
        wait_for_err();
    }

    ASSERT_GE(m_err_count, 1u);
    EXPECT_EQ(3u, conn_retries(ep));
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_statuses[0]);
    EXPECT_EQ(ep, m_err_eps[0]);
    check_failed_ep_invariants(ep);

    progress_for(CONN_TIMEOUT_SEC);
    EXPECT_EQ(-1, try_accept(listen_fd)) << "EP reconnected after failure";
    EXPECT_EQ(3u, conn_retries(ep));

    std::string statuses;
    for (size_t i = 0; i < m_err_statuses.size(); ++i) {
        statuses += std::string(" ") + ucs_status_string(m_err_statuses[i]);
    }
    EXPECT_EQ(1u, m_err_count) << "error callback fired " << m_err_count
                               << " times:" << statuses;

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* Reference path uct_tcp_ep_connect_to_ep_v2() was written for: the peer's
 * CONN_REQ arrives before uct_ep_connect_to_ep() is called (CLOSED ->
 * CONNECTED, conn_retries becomes > 0, EP leaves the PTR map), then the peer
 * disconnects (-> CLOSED, UCS_ERR_CONNECTION_RESET) and only then the user
 * calls uct_ep_connect_to_ep(): it must return UCS_ERR_CONNECTION_RESET.
 * Transitions: pm:connect_to_ep_after_removal (disconnect variant) */
UCS_TEST_P(test_uct_tcp_explore_retries_after_timeout,
           connect_to_ep_after_peer_disconnect)
{
    std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
    std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
    uct_tcp_ep_addr_t *addr = (uct_tcp_ep_addr_t*)&ep_addr[0];
    struct sockaddr_storage peer_addr;
    std::string output;
    size_t fd_count;
    int sig;

    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_connect_to_ep(addr);
    ASSERT_UCS_OK(uct_iface_get_device_address(m_ent->iface(),
                                               (uct_device_addr_t*)&dev_addr[0]));
    EXPECT_EQ(0u, conn_retries(ep));

    /* Raw peer connects and sends magic + CONN_REQ(CONNECT_TO_EP) addressed
     * to our EP. The advertised peer address must be lower than the iface
     * address so that the local side is the accepting one */
    uint16_t iface_port = port_of(iface_addr());
    ASSERT_GT(iface_port, 1);
    memcpy(&peer_addr, iface_addr(), sizeof(peer_addr));
    ASSERT_UCS_OK(ucs_sockaddr_set_port((struct sockaddr*)&peer_addr,
                                        iface_port - 1));

    int fd = raw_connect(iface_addr());
    while (!ucs_socket_is_connected(fd)) {
        progress();
    }

    std::vector<uint8_t> pkt(sizeof(uint64_t) + sizeof(uct_tcp_am_hdr_t) +
                             sizeof(uct_tcp_cm_conn_req_pkt_t) +
                             m_tcp_iface->config.sockaddr_len);
    uint64_t *magic                    = (uint64_t*)&pkt[0];
    uct_tcp_am_hdr_t *hdr              = (uct_tcp_am_hdr_t*)(magic + 1);
    uct_tcp_cm_conn_req_pkt_t *req_pkt = (uct_tcp_cm_conn_req_pkt_t*)(hdr + 1);

    *magic              = UCT_TCP_MAGIC_NUMBER;
    hdr->am_id          = UCT_TCP_EP_CM_AM_ID;
    hdr->length         = sizeof(*req_pkt) + m_tcp_iface->config.sockaddr_len;
    req_pkt->event      = UCT_TCP_CM_CONN_REQ;
    req_pkt->flags      = UCT_TCP_CM_CONN_REQ_PKT_FLAG_CONNECT_TO_EP;
    req_pkt->cm_id.ptr_map_key = addr->ptr_map_key;
    memcpy(req_pkt + 1, &peer_addr, m_tcp_iface->config.sockaddr_len);
    ASSERT_UCS_OK(ucs_socket_send(fd, &pkt[0], pkt.size()));

    wait_for_state(ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
    /* incremented by uct_tcp_cm_handle_conn_req() and uct_tcp_ep_replace_ep()
     * (observed: 2), what matters for connect_to_ep is that it is non-zero */
    unsigned retries_connected = conn_retries(ep);
    EXPECT_GT(retries_connected, 0u);
    EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    /* peer disconnects */
    close(fd);
    m_raw_fds.erase(std::find(m_raw_fds.begin(), m_raw_fds.end(), fd));
    wait_for_err();
    ASSERT_EQ(1u, m_err_count);
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET, m_err_status);
    EXPECT_EQ(ep, m_err_eps[0]);
    EXPECT_EQ(retries_connected, conn_retries(ep));
    check_failed_ep_invariants(ep);

    addr->iface_addr.port = htons(iface_port - 1);
    addr->ptr_map_key     = 0x1234;
    ucs_status_t status   = connect_to_ep_in_child(
            ep, (uct_device_addr_t*)&dev_addr[0], (uct_ep_addr_t*)&ep_addr[0],
            &sig, output);
    UCS_TEST_MESSAGE << "connect_to_ep after peer disconnect (conn_retries="
                     << conn_retries(ep) << "): "
                     << (sig ? strsignal(sig) : ucs_status_string(status))
                     << (output.empty() ? "" : "\n") << output;
    EXPECT_EQ(0, sig) << output;
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET, status);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* CONNECT_TO_EP, local side accepts, peer never sends CONN_REQ: the EP times
 * out in ACCEPTING, is removed from the PTR map and reported. A subsequent
 * uct_ep_connect_to_ep_v2() finds the EP off the map in CLOSED state with
 * conn_retries == 0 (no connect attempt was ever made on an accepting EP).
 * The API contract (same as after a peer disconnect) is
 * UCS_ERR_CONNECTION_RESET without aborting the process.
 * Transitions: pm:connect_to_ep_after_removal (timeout variant) */
UCS_TEST_P(test_uct_tcp_explore_retries_after_timeout,
           connect_to_ep_after_accept_side_timeout)
{
    std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
    std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
    uct_tcp_ep_addr_t *addr = (uct_tcp_ep_addr_t*)&ep_addr[0];
    uct_ep_connect_to_ep_params_t conn_params = {0};
    struct sockaddr_storage listen_addr;
    std::string output;
    size_t fd_count;
    int sig;

    require_conn_timeout();

    if (!lower_raw_listener(&listen_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_connect_to_ep(addr);
    ASSERT_UCS_OK(uct_iface_get_device_address(m_ent->iface(),
                                               (uct_device_addr_t*)&dev_addr[0]));
    addr->iface_addr.port = htons(port_of((struct sockaddr*)&listen_addr));
    addr->ptr_map_key     = 0x1234;

    ASSERT_UCS_OK(uct_ep_connect_to_ep_v2(ep, (uct_device_addr_t*)&dev_addr[0],
                                          (uct_ep_addr_t*)&ep_addr[0],
                                          &conn_params));
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
    EXPECT_EQ(0u, conn_retries(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    wait_for_err();
    ASSERT_EQ(1u, m_err_count);
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    EXPECT_EQ(ep, m_err_eps[0]);
    EXPECT_EQ(0u, conn_retries(ep));
    check_failed_ep_invariants(ep);

    /* The accepting side never connects: nothing may have been sent to the
     * peer listener, before or after the timeout */
    progress_for(CONN_TIMEOUT_SEC);
    EXPECT_EQ(-1, try_accept(m_raw_fds.back()));
    EXPECT_EQ(1u, m_err_count);

    ucs_status_t status = connect_to_ep_in_child(
            ep, (uct_device_addr_t*)&dev_addr[0], (uct_ep_addr_t*)&ep_addr[0],
            &sig, output);
    UCS_TEST_MESSAGE << "connect_to_ep after accept-side timeout (conn_retries="
                     << conn_retries(ep) << "): "
                     << (sig ? strsignal(sig) : ucs_status_string(status))
                     << (output.empty() ? "" : "\n") << output;
    EXPECT_EQ(0, sig) << "uct_ep_connect_to_ep_v2() aborted:\n" << output;
    if (sig == 0) {
        EXPECT_EQ(UCS_ERR_CONNECTION_RESET, status);
    }

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_retries_after_timeout, tcp)
