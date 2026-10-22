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
#include <algorithm>


/**
 * Exploration tests for the interaction between the connection establishment
 * timeout (UCX_TCP_CONN_TIMEOUT) and the EP lifecycle: destroying / closing an
 * EP or the iface while the timeout is armed or already expired, posting TX
 * operations on an expired but not yet swept EP, and re-entrant uct_ep_destroy
 * from the error handler while several deadlines expire in one sweep.
 *
 * Peers are raw sockets which never complete the UCT TCP handshake, so the EP
 * under test is deterministically stuck in WAITING_ACK (or ACCEPTING for an
 * internal EP). Only fields/functions which exist without the timeout feature
 * are used, so the file builds on both branches; timeout specific tests skip
 * when the TCP_CONN_TIMEOUT config is not available.
 */
class test_uct_tcp_close_racing_timeout : public uct_test {
public:
    test_uct_tcp_close_racing_timeout() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_has_conn_timeout(false), m_err_action(ERR_ACTION_NONE)
    {
    }

    void init()
    {
        uct_test::init();
        modify_config("TCP_CONN_TIMEOUT", CONN_TIMEOUT_STR, IGNORE_IF_NOT_EXIST);
        /* same call modify_config() makes, to learn whether the knob exists */
        m_has_conn_timeout = (uct_config_modify(m_iface_config,
                                                "TCP_CONN_TIMEOUT",
                                                CONN_TIMEOUT_STR) == UCS_OK);
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
    typedef enum {
        ERR_ACTION_NONE,
        /* destroy the next still alive EP (not the failed one) */
        ERR_ACTION_DESTROY_NEXT_ALIVE,
        /* destroy the failed EP itself */
        ERR_ACTION_DESTROY_SELF
    } err_action_t;

    static const double CONN_TIMEOUT_SEC;
    static const char  *CONN_TIMEOUT_STR;
    static const double WAIT_TIMEOUT_SEC;

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_close_racing_timeout *self =
                reinterpret_cast<test_uct_tcp_close_racing_timeout*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_eps.push_back(ep);
        self->err_action(ep);
        return UCS_OK;
    }

    void forget_ep(uct_ep_h ep)
    {
        std::vector<uct_ep_h>::iterator it = std::find(m_alive_eps.begin(),
                                                       m_alive_eps.end(), ep);
        if (it != m_alive_eps.end()) {
            m_alive_eps.erase(it);
        }
    }

    void destroy_ep(uct_ep_h ep)
    {
        forget_ep(ep);
        uct_ep_destroy(ep);
    }

    void err_action(uct_ep_h failed_ep)
    {
        if (m_err_action == ERR_ACTION_DESTROY_SELF) {
            destroy_ep(failed_ep);
        } else if (m_err_action == ERR_ACTION_DESTROY_NEXT_ALIVE) {
            /* the failed EP is still alive from the test's point of view
             * (it is destroyed by the test after the callback) */
            for (size_t i = 0; i < m_alive_eps.size(); ++i) {
                if ((m_alive_eps[i] != failed_ep) &&
                    (std::find(m_err_eps.begin(), m_err_eps.end(),
                               m_alive_eps[i]) == m_err_eps.end())) {
                    destroy_ep(m_alive_eps[i]);
                    return;
                }
            }
        }
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
        m_alive_eps.push_back(ep);
        return ep;
    }

    /* @a num EPs stuck in the handshake with a peer which never answers
     * CONN_REQ; returns the fd count to compare against after destroy */
    size_t create_stalled_eps(unsigned num, std::vector<uct_ep_h> &eps)
    {
        struct sockaddr_storage listen_addr;
        size_t fd_count;

        raw_listener(&listen_addr);
        fd_count = open_fd_count();
        for (unsigned i = 0; i < num; ++i) {
            eps.push_back(
                    create_ep_to_port(port_of((struct sockaddr*)&listen_addr)));
            EXPECT_TRUE(conn_in_progress(eps.back()));
        }
        EXPECT_EQ((size_t)num, m_tcp_iface->outstanding);
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));
        return fd_count;
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    static bool conn_in_progress(uct_ep_h ep)
    {
        return (conn_state(ep) == UCT_TCP_EP_CONN_STATE_CONNECTING) ||
               (conn_state(ep) == UCT_TCP_EP_CONN_STATE_WAITING_ACK);
    }

    void skip_without_conn_timeout()
    {
        if (!m_has_conn_timeout) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not available");
        }
    }

    /* Wall clock wait WITHOUT progressing, so that the deadline of every
     * armed EP expires before the next sweep */
    void expire_deadlines()
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(2.5 * CONN_TIMEOUT_SEC);
        while (ucs_get_time() < deadline) {
            sched_yield();
        }
    }

    void wait_for_err(unsigned count = 1)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((m_err_count < count) && (ucs_get_time() < deadline)) {
            progress();
        }
    }

    void progress_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
            progress();
        }
    }

    size_t ep_count_in_state(int state /* -1: any */)
    {
        size_t num = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(m_tcp_iface->super.worker->async);
        ucs_list_for_each(ep, &m_tcp_iface->ep_list, list) {
            num += ((state < 0) || (ep->conn_state == state));
        }
        UCS_ASYNC_UNBLOCK(m_tcp_iface->super.worker->async);
        return num;
    }

    /* Internal RX EP in ACCEPTING: the raw peer connects and sends only the
     * magic number, never CONN_REQ */
    void create_internal_accepting_ep(uct_tcp_ep_t **ep_p, int *fd_p)
    {
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;
        uct_tcp_ep_t *ep = NULL;
        int fd           = raw_connect(iface_addr());

        *ep_p = NULL;

        while (!ucs_socket_is_connected(fd)) {
            progress();
        }
        ASSERT_UCS_OK(ucs_socket_send(fd, &magic, sizeof(magic)));

        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING) == 0) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
        ASSERT_EQ(1u, ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING));

        UCS_ASYNC_BLOCK(m_tcp_iface->super.worker->async);
        ucs_list_for_each(ep, &m_tcp_iface->ep_list, list) {
            if (ep->conn_state == UCT_TCP_EP_CONN_STATE_ACCEPTING) {
                break;
            }
        }
        UCS_ASYNC_UNBLOCK(m_tcp_iface->super.worker->async);
        *fd_p = fd;
        *ep_p = ep;
    }

    void check_idle_iface()
    {
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    }

    /* Leak a user EP in WAITING_ACK into uct_iface_close(). Done as a gtest
     * death test in "threadsafe" style, i.e. in a re-executed child process
     * which owns its own epoll instances (a plain fork() would share them
     * with the parent): on a branch with the timeout feature the iface
     * destructor asserts conn_timeout_list is empty BEFORE
     * ucs_conn_match_cleanup() gets to purge the leaked EP, while without it
     * the purge callback destroys the EP and the close is clean. */
    void iface_close_with_leaked_ep(bool expired)
    {
        std::vector<uct_ep_h> eps;

        create_stalled_eps(1, eps);
        if (expired) {
            expire_deadlines();
        }

        ::testing::FLAGS_gtest_death_test_style = "threadsafe";
        EXPECT_EXIT({
                        /* abort() instead of freezing on a failed assert */
                        ucs_global_opts.handle_errors = 0;
                        uct_iface_close(m_ent->iface());
                        _exit(0);
                    },
                    ::testing::ExitedWithCode(0), "")
                << "uct_iface_close() with a leaked "
                << uct_tcp_ep_cm_state[conn_state(eps[0])].name << " EP";

        /* the parent still owns everything, clean up normally */
        destroy_ep(eps[0]);
        check_idle_iface();
    }

    uct_tcp_iface_t       *m_tcp_iface;
    entity                *m_ent;
    unsigned              m_err_count;
    ucs_status_t          m_err_status;
    bool                  m_has_conn_timeout;
    err_action_t          m_err_action;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<uct_ep_h> m_alive_eps;
    std::vector<int>      m_raw_fds;
};

const double test_uct_tcp_close_racing_timeout::CONN_TIMEOUT_SEC = 0.2;
const char  *test_uct_tcp_close_racing_timeout::CONN_TIMEOUT_STR = "200ms";
const double test_uct_tcp_close_racing_timeout::WAIT_TIMEOUT_SEC = 10.0;


/* (1) Deadline expired but no progress was made (no sweep): uct_ep_destroy
 * must disarm the timeout and release outstanding; later progress must not
 * fire the error callback for the freed EPs */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, destroy_expired_unswept)
{
    const unsigned num_eps = 3;
    std::vector<uct_ep_h> eps;
    size_t fd_count;

    skip_without_conn_timeout();

    fd_count = create_stalled_eps(num_eps, eps);
    expire_deadlines();

    /* nothing was swept yet */
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ((size_t)num_eps, m_tcp_iface->outstanding);
    for (unsigned i = 0; i < num_eps; ++i) {
        EXPECT_TRUE(conn_in_progress(eps[i]));
        EXPECT_EQ(-1, tcp_ep(eps[i])->stale_fd);
    }

    for (unsigned i = 0; i < num_eps; ++i) {
        destroy_ep(eps[i]);
        EXPECT_EQ((size_t)(num_eps - i - 1), m_tcp_iface->outstanding);
    }
    check_idle_iface();
    EXPECT_EQ(fd_count, open_fd_count());

    /* the sweep runs on an empty list: no callback, no touch of freed EPs */
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, m_err_count);
    check_idle_iface();
}

/* Same as above, but the EPs are destroyed before the deadline (armed, not
 * expired); runs on both branches */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, destroy_armed_before_deadline)
{
    const unsigned num_eps = 3;
    std::vector<uct_ep_h> eps;
    size_t fd_count;

    fd_count = create_stalled_eps(num_eps, eps);
    progress();
    EXPECT_EQ(0u, m_err_count);

    for (unsigned i = 0; i < num_eps; ++i) {
        EXPECT_TRUE(conn_in_progress(eps[i]));
        destroy_ep(eps[i]);
    }
    check_idle_iface();
    EXPECT_EQ(fd_count, open_fd_count());

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, m_err_count);
    check_idle_iface();
}

/* (2) uct_iface_close() with a user EP still armed (not expired) */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, iface_close_leaked_armed_ep)
{
    iface_close_with_leaked_ep(false);
}

/* (2) uct_iface_close() with a user EP whose deadline expired but which was
 * never swept */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, iface_close_leaked_expired_ep)
{
    skip_without_conn_timeout();
    iface_close_with_leaked_ep(true);
}

/* (3) TX operations on an expired but not yet swept EP: NO_RESOURCE and
 * EVWRITE armed; the following sweep clears the events and fails the EP,
 * after which the same operations return CONNECTION_RESET */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, tx_on_expired_unswept)
{
    std::vector<uct_ep_h> eps;
    uint64_t hdr = 0;
    size_t fd_count;

    skip_without_conn_timeout();

    fd_count    = create_stalled_eps(1, eps);
    uct_ep_h ep = eps[0];
    expire_deadlines();

    EXPECT_EQ(0u, m_err_count);
    EXPECT_TRUE(conn_in_progress(ep));
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, uct_ep_flush(ep, 0, NULL));
    EXPECT_TRUE(tcp_ep(ep)->events & UCS_EVENT_SET_EVWRITE);
    EXPECT_EQ(UCS_ERR_NO_RESOURCE,
              uct_ep_am_short(ep, 0, hdr, &hdr, sizeof(hdr)));
    EXPECT_TRUE(tcp_ep(ep)->events & UCS_EVENT_SET_EVWRITE);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    wait_for_err();
    ASSERT_EQ(1u, m_err_count);
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    EXPECT_EQ(ep, m_err_eps[0]);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET, uct_ep_flush(ep, 0, NULL));
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET,
              uct_ep_am_short(ep, 0, hdr, &hdr, sizeof(hdr)));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    check_idle_iface();

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);

    destroy_ep(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (4) The error handler destroys another stalled EP on every call while all
 * deadlines expire in one sweep: every EP is either reported exactly once
 * or destroyed by the handler, never both */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, err_cb_destroys_other_eps)
{
    const unsigned num_eps = 6;
    std::vector<uct_ep_h> eps;
    size_t fd_count;

    skip_without_conn_timeout();

    fd_count     = create_stalled_eps(num_eps, eps);
    m_err_action = ERR_ACTION_DESTROY_NEXT_ALIVE;
    expire_deadlines();

    /* one sweep (no readable events on the sockets): callback for EP[0]
     * destroys EP[1], callback for EP[2] destroys EP[3], ... */
    wait_for_err(num_eps / 2);
    EXPECT_EQ(num_eps / 2, m_err_count);
    EXPECT_EQ(num_eps / 2, m_alive_eps.size());
    check_idle_iface();

    std::vector<uct_ep_h> reported(m_err_eps);
    std::sort(reported.begin(), reported.end());
    EXPECT_TRUE(std::unique(reported.begin(), reported.end()) ==
                reported.end());
    for (size_t i = 0; i < m_alive_eps.size(); ++i) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(m_alive_eps[i]));
        EXPECT_EQ(0u, tcp_ep(m_alive_eps[i])->events);
        EXPECT_TRUE(std::find(m_err_eps.begin(), m_err_eps.end(),
                              m_alive_eps[i]) != m_err_eps.end());
    }

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(num_eps / 2, m_err_count);

    while (!m_alive_eps.empty()) {
        destroy_ep(m_alive_eps.back());
    }
    check_idle_iface();
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (4) The error handler destroys the failed EP itself from inside the
 * callback (allowed by the uct_error_handler_t contract: the EP is unusable
 * after the callback). The sweep must not touch the EP after
 * uct_tcp_ep_set_failed() returned. Run under ASAN / valgrind to detect a
 * use-after-free. */
UCS_TEST_P(test_uct_tcp_close_racing_timeout, err_cb_destroys_failed_ep)
{
    const unsigned num_eps = 4;
    std::vector<uct_ep_h> eps;
    size_t fd_count;

    skip_without_conn_timeout();

    fd_count     = create_stalled_eps(num_eps, eps);
    m_err_action = ERR_ACTION_DESTROY_SELF;
    expire_deadlines();

    wait_for_err(num_eps);
    EXPECT_EQ(num_eps, m_err_count);
    EXPECT_EQ(0u, m_alive_eps.size());
    check_idle_iface();
    EXPECT_EQ(fd_count, open_fd_count());

    std::sort(m_err_eps.begin(), m_err_eps.end());
    EXPECT_TRUE(std::unique(m_err_eps.begin(), m_err_eps.end()) ==
                m_err_eps.end());

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(num_eps, m_err_count);
    check_idle_iface();
}

/* An internal (RX only) EP times out in ACCEPTING: it is marked FAILED and a
 * one-shot destroy callback is queued on the worker. Destroying it before
 * the one-shot ran (as the iface destructor does) must remove the one-shot,
 * otherwise the worker later calls into a freed EP */
UCS_TEST_P(test_uct_tcp_close_racing_timeout,
           destroy_failed_internal_ep_before_oneshot)
{
    uct_tcp_ep_t *ep;
    size_t fd_count;
    int fd;

    skip_without_conn_timeout();

    fd_count = open_fd_count();
    create_internal_accepting_ep(&ep, &fd);
    ASSERT_TRUE(ep != NULL);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    expire_deadlines();

    /* a single call of the transport progress function: the sweep queues the
     * one-shot destroy, which only runs on the next worker progress */
    uct_iface_progress(m_ent->iface());
    ASSERT_EQ(1u, ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING));
    EXPECT_TRUE(ep->flags & UCT_TCP_EP_FLAG_FAILED);
    EXPECT_EQ(0u, ep->events);
    EXPECT_EQ(0u, m_err_count);
    /* a FAILED internal EP stays in ACCEPTING (and counted in outstanding)
     * until the deferred destroy runs */
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    uct_tcp_ep_destroy_internal(&ep->super.super);
    EXPECT_EQ(0u, ep_count_in_state(-1));
    check_idle_iface();

    /* the one-shot must be gone: the worker progress must not touch the
     * freed EP (ASAN / valgrind) and must not destroy it twice */
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, ep_count_in_state(-1));
    EXPECT_EQ(0u, m_err_count);
    check_idle_iface();

    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_close_racing_timeout, tcp)
