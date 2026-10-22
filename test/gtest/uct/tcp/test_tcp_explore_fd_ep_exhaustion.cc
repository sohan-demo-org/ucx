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

#include <sys/resource.h>
#include <dirent.h>
#include <fcntl.h>
#include <algorithm>


/**
 * Exploratory tests for fd / EP exhaustion around the TCP connection
 * establishment timeout (UCX_TCP_CONN_TIMEOUT): mass stalls with hundreds of
 * user and internal EPs, socket()/accept() failing under RLIMIT_NOFILE
 * pressure, and iface destruction while EPs are armed / failed-but-not-yet
 * destroyed. Peers are raw sockets which never complete the UCT TCP protocol.
 * Only fields which exist with and without the timeout feature are used, so
 * the file compiles on both; timeout specific tests skip when the config knob
 * is absent.
 *
 * NOTE: the last two tests damage the process on purpose when they fail:
 * iface_destroy_with_armed_user_ep trips a ucs_assert in the iface cleanup
 * (UCX_HANDLE_ERRORS=freeze stops the process) and accept_emfile leaves an
 * async handler behind which makes every later TCP iface creation in this
 * process fail. Run them with their own --gtest_filter.
 */
class test_uct_tcp_explore_fd_ep_exhaustion : public uct_test {
public:
    test_uct_tcp_explore_fd_ep_exhaustion() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0),
        m_nofile_lowered(false), m_has_conn_timeout(false),
        m_expect_cleanup_warn(false)
    {
    }

    void init()
    {
        std::string value;

        uct_test::init();
        /* Must be done before the iface is created; absent without the
         * connection timeout feature */
        modify_config("TCP_CONN_TIMEOUT", "500ms", IGNORE_IF_NOT_EXIST);
        m_has_conn_timeout = get_config("CONN_TIMEOUT", value);
        m_ent = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_ent);
        m_tcp_iface = ucs_derived_of(m_ent->iface(), uct_tcp_iface_t);
    }

    void cleanup()
    {
        restore_nofile_limit();
        close_fds(m_raw_fds);
        if (m_expect_cleanup_warn) {
            scoped_log_handler slh(wrap_warns_logger);
            uct_test::cleanup();
        } else {
            uct_test::cleanup();
        }
    }

protected:
    static const double CONN_TIMEOUT_SEC;
    static const double WAIT_TIMEOUT_SEC;

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_fd_ep_exhaustion *self =
                reinterpret_cast<test_uct_tcp_explore_fd_ep_exhaustion*>(arg);

        self->m_err_count++;
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

    static int max_open_fd()
    {
        DIR *dir = opendir("/proc/self/fd");
        struct dirent *de;
        int max_fd = -1;

        EXPECT_TRUE(dir != NULL);
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] != '.') {
                max_fd = std::max(max_fd, atoi(de->d_name));
            }
        }
        closedir(dir);
        return max_fd;
    }

    /* Fill every free fd number below the current maximum with /dev/null and
     * lower the soft RLIMIT_NOFILE to (max fd + 1), so that the next
     * socket()/accept()/open() fails with EMFILE. Restored by
     * restore_nofile_limit() (also called from cleanup()). */
    void exhaust_fds()
    {
        struct rlimit rl;
        int max_fd, fd;

        ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &m_saved_rlimit));
        max_fd = max_open_fd();
        for (;;) {
            fd = open("/dev/null", O_RDONLY);
            ASSERT_TRUE(fd >= 0);
            m_dummy_fds.push_back(fd);
            if (fd > max_fd) {
                break;
            }
        }

        rl.rlim_cur = fd + 1;
        rl.rlim_max = m_saved_rlimit.rlim_max;
        ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &rl));
        m_nofile_lowered = true;

        /* sanity: no fd can be allocated anymore */
        fd = open("/dev/null", O_RDONLY);
        EXPECT_EQ(-1, fd);
        EXPECT_EQ(EMFILE, errno);
        if (fd != -1) {
            close(fd);
        }
    }

    void restore_nofile_limit()
    {
        if (m_nofile_lowered) {
            EXPECT_EQ(0, setrlimit(RLIMIT_NOFILE, &m_saved_rlimit));
            m_nofile_lowered = false;
        }
        close_fds(m_dummy_fds);
    }

    static const struct sockaddr *iface_addr_of(uct_tcp_iface_t *iface)
    {
        return (const struct sockaddr*)&iface->config.ifaddr;
    }

    const struct sockaddr *iface_addr() const
    {
        return iface_addr_of(m_tcp_iface);
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

    int raw_socket(const struct sockaddr *addr)
    {
        int fd = socket(addr->sa_family, SOCK_STREAM, 0);
        EXPECT_TRUE(fd >= 0);
        m_raw_fds.push_back(fd);
        return fd;
    }

    /* Blocking connect() with the raw syscalls (no UCS logging) on @a fd (a
     * new socket if -1): returns 0 on success or -errno */
    int raw_connect_blocking_result(const struct sockaddr *addr, int fd = -1)
    {
        size_t addr_size;
        int ret;

        ASSERT_UCS_OK(ucs_sockaddr_sizeof(addr, &addr_size));
        if (fd == -1) {
            fd = raw_socket(addr);
        }
        ret = connect(fd, addr, addr_size);
        return (ret == 0) ? 0 : -errno;
    }

    uint16_t port_of(const struct sockaddr *addr)
    {
        uint16_t port = 0;
        EXPECT_UCS_OK(ucs_sockaddr_get_port(addr, &port));
        return port;
    }

    /* CONNECT_TO_IFACE EP from @a ent to a peer listening on @a port on the
     * iface IP; returns the status of uct_ep_create() */
    ucs_status_t create_ep_to_port(entity *ent, uint16_t port, uct_ep_h *ep_p)
    {
        std::vector<uint8_t> dev_addr(ent->iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;

        EXPECT_UCS_OK(uct_iface_get_device_address(ent->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        iface_addr.port   = htons(port);
        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = ent->iface();
        params.dev_addr   = (uct_device_addr_t*)&dev_addr[0];
        params.iface_addr = (uct_iface_addr_t*)&iface_addr;
        return uct_ep_create(&params, ep_p);
    }

    uct_ep_h create_ep_to_port(uint16_t port)
    {
        uct_ep_h ep = NULL;
        EXPECT_UCS_OK(create_ep_to_port(m_ent, port, &ep));
        return ep;
    }

    /* @a num raw clients which connect to @a iface and send only the magic
     * number, so that the iface creates internal RX EPs stuck in ACCEPTING.
     * Returns once all of them are connected and the magic has been sent. */
    void raw_clients_magic_only(entity *ent, uct_tcp_iface_t *iface,
                                unsigned num)
    {
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;
        std::vector<int> fds;

        for (unsigned i = 0; i < num; ++i) {
            fds.push_back(raw_connect(iface_addr_of(iface)));
        }

        for (unsigned i = 0; i < num; ++i) {
            while (!ucs_socket_is_connected(fds[i])) {
                ent->progress();
            }
            ASSERT_UCS_OK(ucs_socket_send(fds[i], &magic, sizeof(magic)));
        }
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    void wait_for_err(unsigned count)
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

    /* Number of EPs on the iface's EP list matching @a state (any state if
     * negative) and @a flags (all of them) */
    static size_t ep_list_count(uct_tcp_iface_t *iface, int state = -1,
                                uint16_t flags = 0)
    {
        size_t num = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(iface->super.worker->async);
        ucs_list_for_each(ep, &iface->ep_list, list) {
            if (((state < 0) || (ep->conn_state == state)) &&
                ucs_test_all_flags(ep->flags, flags)) {
                ++num;
            }
        }
        UCS_ASYNC_UNBLOCK(iface->super.worker->async);
        return num;
    }

    size_t ep_count()
    {
        return ep_list_count(m_tcp_iface);
    }

    template <typename Pred>
    void wait_until(Pred pred, entity *ent = NULL)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!pred() && (ucs_get_time() < deadline)) {
            if (ent != NULL) {
                ent->progress();
            } else {
                progress();
            }
        }
    }

    struct ep_count_is {
        ep_count_is(uct_tcp_iface_t *iface, size_t count) :
            m_iface(iface), m_count(count) {}
        bool operator()() const { return ep_list_count(m_iface) == m_count; }
        uct_tcp_iface_t *m_iface;
        size_t          m_count;
    };

    struct ep_count_in_state_is {
        ep_count_in_state_is(uct_tcp_iface_t *iface, int state, size_t count) :
            m_iface(iface), m_state(state), m_count(count) {}
        bool operator()() const {
            return ep_list_count(m_iface, m_state) == m_count;
        }
        uct_tcp_iface_t *m_iface;
        int             m_state;
        size_t          m_count;
    };

    void skip_without_conn_timeout()
    {
        if (!m_has_conn_timeout) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
        }
    }

    uct_tcp_iface_t          *m_tcp_iface;
    entity                   *m_ent;
    unsigned                 m_err_count;
    std::vector<uct_ep_h>    m_err_eps;
    std::vector<ucs_status_t> m_err_statuses;
    std::vector<int>         m_raw_fds;
    std::vector<int>         m_dummy_fds;
    struct rlimit            m_saved_rlimit;
    bool                     m_nofile_lowered;
    bool                     m_has_conn_timeout;
    bool                     m_expect_cleanup_warn;
};

const double test_uct_tcp_explore_fd_ep_exhaustion::CONN_TIMEOUT_SEC = 0.5;
const double test_uct_tcp_explore_fd_ep_exhaustion::WAIT_TIMEOUT_SEC = 20.0;


/* (1) Mass stall: hundreds of CONNECT_TO_IFACE EPs to a raw listener which
 * never answers CONN_REQ (WAITING_ACK) plus hundreds of raw clients which send
 * only the magic number (internal EPs stuck in ACCEPTING), created in
 * interleaved batches so that the deadlines differ. Every user EP must be
 * reported exactly once, the internal EPs must vanish, outstanding must drop
 * to zero and no fd may leak once the user EPs are destroyed. */
UCS_TEST_P(test_uct_tcp_explore_fd_ep_exhaustion, mass_stall_interleaved)
{
    const unsigned num_batches = 4;
    const unsigned batch_size  = 64;
    const unsigned num_eps     = num_batches * batch_size;
    struct sockaddr_storage listen_addr;
    std::vector<uct_ep_h> eps;
    size_t fd_count;

    skip_without_conn_timeout();

    fd_count = open_fd_count();
    raw_listener(&listen_addr, 2 * num_eps);

    for (unsigned b = 0; b < num_batches; ++b) {
        for (unsigned i = 0; i < batch_size; ++i) {
            eps.push_back(create_ep_to_port(port_of((struct sockaddr*)&listen_addr)));
        }
        raw_clients_magic_only(m_ent, m_tcp_iface, batch_size);
        /* let the internal EPs of this batch reach ACCEPTING and spread the
         * deadlines of the batches */
        wait_until(ep_count_in_state_is(m_tcp_iface,
                                        UCT_TCP_EP_CONN_STATE_ACCEPTING,
                                        (b + 1) * batch_size));
        progress_for(CONN_TIMEOUT_SEC / 8);
    }

    /* EXPECT, not ASSERT: leaving the user EPs undestroyed trips the iface
     * cleanup (see iface_destroy_with_armed_user_ep) */
    EXPECT_EQ((size_t)num_eps, ep_list_count(m_tcp_iface,
                                             UCT_TCP_EP_CONN_STATE_ACCEPTING));
    for (unsigned i = 0; i < num_eps; ++i) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(eps[i]));
    }
    /* user EPs are on the connection matching context, internal ones on the
     * EP list */
    EXPECT_EQ((size_t)num_eps, ep_count());
    EXPECT_EQ(2 * num_eps, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    wait_for_err(num_eps);
    ASSERT_EQ(num_eps, m_err_count);
    for (unsigned i = 0; i < num_eps; ++i) {
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_statuses[i]);
    }

    /* every user EP reported exactly once */
    std::vector<uct_ep_h> reported(m_err_eps), created(eps);
    std::sort(reported.begin(), reported.end());
    std::sort(created.begin(), created.end());
    EXPECT_TRUE(reported == created);

    /* internal EPs are destroyed by the deferred one-shot; failed user EPs
     * were moved to the EP list and stay there until destroyed */
    wait_until(ep_count_is(m_tcp_iface, num_eps));
    EXPECT_EQ((size_t)num_eps, ep_count());
    EXPECT_EQ(0u, ep_list_count(m_tcp_iface, UCT_TCP_EP_CONN_STATE_ACCEPTING));
    EXPECT_EQ(0u, ep_list_count(m_tcp_iface, -1, UCT_TCP_EP_FLAG_FAILED));
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    for (unsigned i = 0; i < num_eps; ++i) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(eps[i]));
        EXPECT_EQ(0u, tcp_ep(eps[i])->events);
        EXPECT_EQ(-1, tcp_ep(eps[i])->stale_fd);
        /* the socket is kept until the user destroys the EP */
        EXPECT_NE(-1, tcp_ep(eps[i])->fd);
    }

    /* no re-fire */
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(num_eps, m_err_count);

    for (unsigned i = 0; i < num_eps; ++i) {
        uct_ep_destroy(eps[i]);
    }
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (2a) RLIMIT_NOFILE pressure on uct_ep_create(): socket() fails with EMFILE
 * on the first connection attempt. The user gets an error and no EP, so the
 * iface must not keep anything for that connection: no EP on the EP list, no
 * outstanding unit. With the connection timeout the leftover must at least be
 * reclaimed once the deadline expires. */
UCS_TEST_P(test_uct_tcp_explore_fd_ep_exhaustion, ep_create_emfile_first_attempt)
{
    const unsigned num_attempts = 3;
    struct sockaddr_storage listen_addr;
    uct_ep_h ep = NULL;
    size_t fd_count;
    ucs_status_t status;

    raw_listener(&listen_addr);
    fd_count = open_fd_count();
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    exhaust_fds();
    for (unsigned i = 0; i < num_attempts; ++i) {
        scoped_log_handler slh(wrap_errors_logger);
        status = create_ep_to_port(m_ent, port_of((struct sockaddr*)&listen_addr),
                                   &ep);
        EXPECT_EQ(UCS_ERR_IO_ERROR, status);
    }
    restore_nofile_limit();
    EXPECT_EQ(fd_count, open_fd_count());

    /* Invariant: a failed uct_ep_create() must not leave anything behind */
    UCS_TEST_MESSAGE << "after " << num_attempts << " failed uct_ep_create(): "
                     << ep_count() << " EPs on ep_list ("
                     << ep_list_count(m_tcp_iface,
                                      UCT_TCP_EP_CONN_STATE_CONNECTING)
                     << " CONNECTING), outstanding="
                     << m_tcp_iface->outstanding;
    EXPECT_EQ(0u, ep_count()) << "EP leaked by failed uct_ep_create()";
    EXPECT_EQ(0u, m_tcp_iface->outstanding)
            << "outstanding leaked by failed uct_ep_create()";
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    if (!m_has_conn_timeout) {
        /* nothing can reclaim the leftover EPs; they are destroyed by the
         * iface cleanup */
        return;
    }

    /* The leftover EP is CONNECTING with fd == -1 and no TX capability: the
     * timeout must destroy it as an internal EP without any error callback */
    wait_until(ep_count_is(m_tcp_iface, 0));
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    EXPECT_EQ(fd_count, open_fd_count());

    /* the iface is still usable: a new EP can be created and stalls normally */
    ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    wait_for_err(1);
    EXPECT_EQ(1u, m_err_count);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (3) Destroy an iface while it holds: internal ACCEPTING EPs which already
 * timed out but whose deferred destroy one-shot did not run yet (only
 * uct_iface_progress() is called, not the worker), internal ACCEPTING EPs
 * which are still armed, and the leftover CONNECTING EP of a failed
 * uct_ep_create(). No assert, no error callback, no fd leak, and the worker
 * must not run a one-shot for a destroyed EP afterwards. */
UCS_TEST_P(test_uct_tcp_explore_fd_ep_exhaustion, iface_destroy_with_failed_and_armed_eps)
{
    const unsigned batch_size = 8;
    struct sockaddr_storage listen_addr;
    uct_tcp_iface_t *iface2;
    entity *ent2;
    uct_ep_h ep = NULL;
    size_t fd_count;

    skip_without_conn_timeout();

    fd_count = open_fd_count();
    raw_listener(&listen_addr);
    ent2     = uct_test::create_entity(0, err_handler);
    iface2   = ucs_derived_of(ent2->iface(), uct_tcp_iface_t);

    /* leftover of a failed first connection attempt: CONNECTING, fd == -1 */
    exhaust_fds();
    {
        scoped_log_handler slh(wrap_errors_logger);
        EXPECT_EQ(UCS_ERR_IO_ERROR,
                  create_ep_to_port(ent2, port_of((struct sockaddr*)&listen_addr),
                                    &ep));
    }
    restore_nofile_limit();
    EXPECT_EQ(1u, ep_list_count(iface2, UCT_TCP_EP_CONN_STATE_CONNECTING));

    /* batch A: internal ACCEPTING EPs which will expire first */
    raw_clients_magic_only(ent2, iface2, batch_size);
    wait_until(ep_count_in_state_is(iface2, UCT_TCP_EP_CONN_STATE_ACCEPTING,
                                    batch_size), ent2);
    ucs_time_t batch_a_time = ucs_get_time();

    /* batch B: internal ACCEPTING EPs armed CONN_TIMEOUT/2 later */
    while (ucs_get_time() < batch_a_time + ucs_time_from_sec(CONN_TIMEOUT_SEC / 2)) {
        ent2->progress();
    }
    raw_clients_magic_only(ent2, iface2, batch_size);
    wait_until(ep_count_in_state_is(iface2, UCT_TCP_EP_CONN_STATE_ACCEPTING,
                                    2 * batch_size), ent2);
    EXPECT_EQ(2 * batch_size + 1, iface2->outstanding);

    /* Sweep with the iface progress only: the expired EPs get FLAG_FAILED and
     * a destroy one-shot on the worker, which is not progressed here */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(WAIT_TIMEOUT_SEC);
    while ((ep_list_count(iface2, -1, UCT_TCP_EP_FLAG_FAILED) < batch_size + 1) &&
           (ucs_get_time() < deadline)) {
        uct_iface_progress(ent2->iface());
    }
    size_t num_failed = ep_list_count(iface2, -1, UCT_TCP_EP_FLAG_FAILED);
    size_t num_armed  = ep_list_count(iface2, UCT_TCP_EP_CONN_STATE_ACCEPTING) -
                        ep_list_count(iface2, UCT_TCP_EP_CONN_STATE_ACCEPTING,
                                      UCT_TCP_EP_FLAG_FAILED);
    UCS_TEST_MESSAGE << "failed-not-destroyed=" << num_failed
                     << " still-armed=" << num_armed;
    EXPECT_GE(num_failed, batch_size + 1);
    if (num_armed == 0) {
        delete ent2;
        UCS_TEST_SKIP_R("all EPs expired before the iface was destroyed");
    }
    EXPECT_EQ(2 * batch_size + 1, ep_list_count(iface2));
    EXPECT_EQ(0u, m_err_count);

    /* failed-but-not-destroyed internal EPs keep conn_state ACCEPTING and
     * stay counted in outstanding until the deferred destroy runs */
    EXPECT_EQ(num_armed + num_failed, iface2->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(ent2->iface(), 0, NULL));

    delete ent2;

    /* progress the remaining worker(s): no one-shot for a destroyed EP */
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, m_err_count);

    close_fds(m_raw_fds);
    /* ent2 (listening socket, event set, accepted sockets) is gone as well */
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (3b) Destroy an iface while a user CONNECT_TO_IFACE EP is still armed
 * (WAITING_ACK, on the connection matching context, never destroyed by the
 * user). Without a timeout the EP is purged by ucs_conn_match_cleanup(). */
UCS_TEST_P(test_uct_tcp_explore_fd_ep_exhaustion, iface_destroy_with_armed_user_ep)
{
    struct sockaddr_storage listen_addr;
    uct_tcp_iface_t *iface2;
    entity *ent2;
    uct_ep_h ep = NULL;
    size_t fd_count;

    fd_count = open_fd_count();
    raw_listener(&listen_addr);
    ent2     = uct_test::create_entity(0, err_handler);
    iface2   = ucs_derived_of(ent2->iface(), uct_tcp_iface_t);

    ASSERT_UCS_OK(create_ep_to_port(ent2, port_of((struct sockaddr*)&listen_addr),
                                    &ep));
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, iface2->outstanding);
    EXPECT_EQ(0u, ep_list_count(iface2)); /* on the matching context */

    delete ent2; /* the EP is destroyed by the iface cleanup */

    EXPECT_EQ(0u, m_err_count);
    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (2b) RLIMIT_NOFILE pressure on the listener: accept() fails with EMFILE in
 * the async connect handler. Checks what happens to the listening socket. */
UCS_TEST_P(test_uct_tcp_explore_fd_ep_exhaustion, accept_emfile)
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;
    int listen_fd_before, ret;

    fd_count         = open_fd_count();
    raw_listener(&listen_addr);
    listen_fd_before = m_tcp_iface->listen_fd;
    ASSERT_NE(-1, listen_fd_before);

    /* the client socket must exist before the fds are exhausted */
    int client_fd = raw_socket(iface_addr());
    exhaust_fds();
    {
        scoped_log_handler slh(wrap_errors_logger);
        /* the kernel completes the handshake, accept() fails with EMFILE */
        EXPECT_EQ(0, raw_connect_blocking_result(iface_addr(), client_fd));

        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((m_tcp_iface->listen_fd == listen_fd_before) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
    }
    restore_nofile_limit();

    UCS_TEST_MESSAGE << "listen_fd before=" << listen_fd_before
                     << " after accept() EMFILE=" << m_tcp_iface->listen_fd;
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    /* Invariant: the iface must stay reachable after a transient EMFILE */
    ret = raw_connect_blocking_result(iface_addr());
    EXPECT_EQ(0, ret) << "connect() to the iface after accept() EMFILE: "
                      << strerror(-ret);
    if (ret == 0) {
        /* the iface still accepts: a magic-only client creates an EP */
        raw_clients_magic_only(m_ent, m_tcp_iface, 1);
        wait_until(ep_count_in_state_is(m_tcp_iface,
                                        UCT_TCP_EP_CONN_STATE_ACCEPTING, 1));
        EXPECT_EQ(1u, ep_count());
    } else {
        EXPECT_EQ(-1, m_tcp_iface->listen_fd);
        /* uct_tcp_iface_t cleanup warns when removing the async handler of
         * the already closed listening socket */
        m_expect_cleanup_warn = true;
    }

    close_fds(m_raw_fds);
    if (m_has_conn_timeout) {
        wait_until(ep_count_is(m_tcp_iface, 0));
        EXPECT_EQ(0u, ep_count());
        EXPECT_EQ(fd_count - ((m_tcp_iface->listen_fd == -1) ? 1 : 0),
                  open_fd_count());
    }
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_fd_ep_exhaustion, tcp)
