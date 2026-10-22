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
#include <type_traits>


/**
 * Explore unit "successful_connect_disarm": with UCX_TCP_CONN_TIMEOUT set,
 * every successful handshake (CONNECT_TO_IFACE, CONNECT_TO_EP in both orders
 * of uct_ep_connect_to_ep_v2(), peer's CONN_REQ arriving before the local
 * uct_ep_create()) must arm and then disarm the connection timeout, leave
 * outstanding == 0, keep stale_fd == -1 and never fire the error callback.
 * Destroying a stalled EP before the deadline must disarm it as well.
 *
 * The file compiles on master too: the PR-only fields (conn_deadline on the
 * EP, conn_timeout_list on the iface) are accessed through SFINAE helpers
 * which degrade to "true" when the field does not exist.
 */
namespace {

template <typename T> struct has_conn_deadline {
    template <typename U> static char test(decltype(&U::conn_deadline));
    template <typename U> static long test(...);
    enum { value = (sizeof(test<T>(0)) == sizeof(char)) };
};

template <typename T> struct has_conn_timeout_list {
    template <typename U> static char test(decltype(&U::conn_timeout_list));
    template <typename U> static long test(...);
    enum { value = (sizeof(test<T>(0)) == sizeof(char)) };
};

/* true when the EP is not armed: on master always true */
template <typename Ep>
typename std::enable_if<has_conn_deadline<Ep>::value, bool>::type
ep_timeout_disarmed(const Ep *ep)
{
    return ep->conn_deadline == UCS_TIME_INFINITY;
}

template <typename Ep>
typename std::enable_if<!has_conn_deadline<Ep>::value, bool>::type
ep_timeout_disarmed(const Ep*)
{
    return true;
}

/* true when the iface tracks no EP for timeout: on master always true */
template <typename Iface>
typename std::enable_if<has_conn_timeout_list<Iface>::value, bool>::type
iface_timeout_list_empty(const Iface *iface)
{
    return ucs_list_is_empty(&iface->conn_timeout_list);
}

template <typename Iface>
typename std::enable_if<!has_conn_timeout_list<Iface>::value, bool>::type
iface_timeout_list_empty(const Iface*)
{
    return true;
}

const bool have_conn_timeout_fields =
        has_conn_deadline<uct_tcp_ep_t>::value &&
        has_conn_timeout_list<uct_tcp_iface_t>::value;

} // namespace


class test_uct_tcp_explore_connect_disarm : public uct_test {
public:
    test_uct_tcp_explore_connect_disarm() :
        m_e0(NULL), m_e1(NULL), m_err_count(0), m_has_conn_timeout(false)
    {
        m_am_count[0] = m_am_count[1] = 0;
    }

    void init()
    {
        std::string value;

        uct_test::init();
        modify_config("TCP_CONN_TIMEOUT", "200ms", IGNORE_IF_NOT_EXIST);
        /* uct_config_get() takes the name without the table prefix */
        m_has_conn_timeout = get_config("CONN_TIMEOUT", value) ||
                             get_config("TCP_CONN_TIMEOUT", value);

        m_e0 = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_e0);
        m_e1 = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_e1);

        check_caps_skip(UCT_IFACE_FLAG_AM_SHORT | UCT_IFACE_FLAG_CB_SYNC);
        uct_iface_set_am_handler(m_e0->iface(), 0, am_handler,
                                 (void*)&m_am_count[0],
                                 0);
        uct_iface_set_am_handler(m_e1->iface(), 0, am_handler,
                                 (void*)&m_am_count[1],
                                 0);
    }

    void cleanup()
    {
        close_fds(m_raw_fds);
        uct_test::cleanup();
    }

protected:
    static const double CONN_TIMEOUT_SEC;
    static const double WAIT_TIMEOUT_SEC;

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_connect_disarm *self =
                reinterpret_cast<test_uct_tcp_explore_connect_disarm*>(arg);

        self->m_err_count++;
        self->m_err_eps.push_back(ep);
        return UCS_OK;
    }

    static ucs_status_t am_handler(void *arg, void *data, size_t length,
                                   unsigned flags)
    {
        volatile unsigned *count = reinterpret_cast<volatile unsigned*>(arg);
        ++*count;
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

    static uct_tcp_iface_t *tcp_iface(entity *e)
    {
        return ucs_derived_of(e->iface(), uct_tcp_iface_t);
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    static bool conn_in_progress(uct_tcp_ep_conn_state_t state)
    {
        return (state == UCT_TCP_EP_CONN_STATE_CONNECTING) ||
               (state == UCT_TCP_EP_CONN_STATE_WAITING_ACK) ||
               (state == UCT_TCP_EP_CONN_STATE_ACCEPTING);
    }

    static const struct sockaddr *iface_addr(entity *e)
    {
        return (const struct sockaddr*)&tcp_iface(e)->config.ifaddr;
    }

    uint16_t port_of(const struct sockaddr *addr)
    {
        uint16_t port = 0;
        EXPECT_UCS_OK(ucs_sockaddr_get_port(addr, &port));
        return port;
    }

    /* Listening socket on the iface IP address which never accepts the
     * connection and never speaks the UCT TCP protocol */
    int raw_listener(struct sockaddr_storage *addr)
    {
        socklen_t addr_len;
        size_t addr_size;
        int fd;

        memcpy(addr, iface_addr(m_e0), sizeof(*addr));
        ASSERT_UCS_OK(ucs_sockaddr_set_port((struct sockaddr*)addr, 0));
        ASSERT_UCS_OK(ucs_sockaddr_sizeof((struct sockaddr*)addr, &addr_size));
        ASSERT_UCS_OK(ucs_socket_create(addr->ss_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);

        EXPECT_EQ(0, bind(fd, (struct sockaddr*)addr, addr_size));
        EXPECT_EQ(0, listen(fd, 16));
        ASSERT_UCS_OK(ucs_socket_getname(fd, addr, &addr_len));
        return fd;
    }

    /* CONNECT_TO_IFACE EP from @a e to a peer listening on @a port */
    uct_ep_h create_ep_to_port(entity *e, uint16_t port)
    {
        std::vector<uint8_t> dev_addr(e->iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;
        uct_ep_h ep;

        uct_device_addr_t *dev_addr_p = (uct_device_addr_t*)&dev_addr[0];

        ASSERT_UCS_OK(uct_iface_get_device_address(e->iface(), dev_addr_p));
        iface_addr.port   = htons(port);
        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = e->iface();
        params.dev_addr   = dev_addr_p;
        params.iface_addr = (uct_iface_addr_t*)&iface_addr;
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    /* CONNECT_TO_IFACE EP from @a from to the iface of @a to */
    uct_ep_h create_ep_to_iface(entity *from, entity *to)
    {
        return create_ep_to_port(from, port_of(iface_addr(to)));
    }

    /* CONNECT_TO_EP EP (not connected yet) on @a e */
    uct_ep_h create_c2e_ep(entity *e)
    {
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = e->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    void connect_c2e(uct_ep_h from, uct_ep_h to)
    {
        uct_iface_attr_t iface_attr;
        ASSERT_UCS_OK(uct_iface_query(to->iface, &iface_attr));

        std::vector<uint8_t> dev_addr(iface_attr.device_addr_len);
        std::vector<uint8_t> ep_addr(iface_attr.ep_addr_len);
        uct_ep_connect_to_ep_params_t params = {0};

        uct_device_addr_t *dev_addr_p = (uct_device_addr_t*)&dev_addr[0];
        uct_ep_addr_t *ep_addr_p      = (uct_ep_addr_t*)&ep_addr[0];

        ASSERT_UCS_OK(uct_iface_get_device_address(to->iface, dev_addr_p));
        ASSERT_UCS_OK(uct_ep_get_address(to, ep_addr_p));
        ASSERT_UCS_OK(uct_ep_connect_to_ep_v2(from, dev_addr_p, ep_addr_p,
                                              &params));
    }

    /* The side whose iface address is greater accepts the connection */
    bool e0_accepts() const
    {
        ucs_status_t status;
        int cmp = ucs_sockaddr_cmp(iface_addr(m_e0), iface_addr(m_e1), &status);
        EXPECT_UCS_OK(status);
        EXPECT_NE(0, cmp);
        return cmp > 0;
    }

    void wait_for_state(uct_ep_h ep, uct_tcp_ep_conn_state_t state)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((conn_state(ep) != state) && (ucs_get_time() < deadline)) {
            progress();
        }
        ASSERT_EQ(state, conn_state(ep));
    }

    /* Progress for @a sec seconds, wall clock */
    void progress_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
            progress();
        }
    }

    size_t ep_count(entity *e)
    {
        uct_tcp_iface_t *iface = tcp_iface(e);
        size_t num             = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(iface->super.worker->async);
        ucs_list_for_each(ep, &iface->ep_list, list) {
            ++num;
        }
        UCS_ASYNC_UNBLOCK(iface->super.worker->async);
        return num;
    }

    size_t ep_count_in_state(entity *e, uct_tcp_ep_conn_state_t state)
    {
        uct_tcp_iface_t *iface = tcp_iface(e);
        size_t num             = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(iface->super.worker->async);
        ucs_list_for_each(ep, &iface->ep_list, list) {
            num += (ep->conn_state == state);
        }
        UCS_ASYNC_UNBLOCK(iface->super.worker->async);
        return num;
    }

    void wait_for_ep_count(entity *e, size_t count)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((ep_count(e) != count) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_EQ(count, ep_count(e));
    }

    void wait_for_fd_count(size_t count)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((open_fd_count() != count) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_EQ(count, open_fd_count());
    }

    /* Invariants on an iface which has no handshake in progress anymore:
     * no EP in a handshake state on ep_list, every EP on ep_list disarmed,
     * the timeout list is empty, outstanding is 0 and flush completes */
    void check_iface_idle(entity *e)
    {
        uct_tcp_iface_t *iface = tcp_iface(e);
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(iface->super.worker->async);
        ucs_list_for_each(ep, &iface->ep_list, list) {
            uct_tcp_ep_conn_state_t state =
                    (uct_tcp_ep_conn_state_t)ep->conn_state;

            EXPECT_FALSE(conn_in_progress(state))
                    << "ep " << ep << " state " << (int)state;
            EXPECT_TRUE(ep_timeout_disarmed(ep)) << "ep " << ep;
            EXPECT_EQ(-1, ep->stale_fd) << "ep " << ep;
            if (ep->events != 0) {
                EXPECT_NE(-1, ep->fd) << "ep " << ep;
            }
        }
        UCS_ASYNC_UNBLOCK(iface->super.worker->async);

        EXPECT_TRUE(iface_timeout_list_empty(iface));
        EXPECT_EQ(0u, iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(e->iface(), 0, NULL));
    }

    /* Invariants on a user EP which completed the handshake */
    void check_connected_ep(uct_ep_h ep)
    {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
        EXPECT_TRUE(ep_timeout_disarmed(tcp_ep(ep)));
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_NE(-1, tcp_ep(ep)->fd);
        EXPECT_NE(0u, tcp_ep(ep)->events);
    }

    /* Positive control: an EP in a handshake state must be armed when the
     * timeout is configured (so the disarm checks are not vacuous) */
    void check_armed_ep(uct_ep_h ep)
    {
        EXPECT_TRUE(conn_in_progress(conn_state(ep)))
                << "state " << (int)conn_state(ep);
        if (m_has_conn_timeout && have_conn_timeout_fields) {
            EXPECT_FALSE(ep_timeout_disarmed(tcp_ep(ep)));
            EXPECT_FALSE(iface_timeout_list_empty(
                    ucs_derived_of(ep->iface, uct_tcp_iface_t)));
        }
    }

    /* Sends one AM from @a ep and waits for it on the peer @a to */
    void send_recv_am(uct_ep_h ep, entity *to)
    {
        volatile unsigned *count = (to == m_e0) ? &m_am_count[0] :
                                                  &m_am_count[1];
        unsigned before          = *count;
        uint64_t data            = 0xdeadbeefull;
        ucs_time_t deadline      = ucs_get_time() +
                                   ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        ucs_status_t status;

        do {
            status = uct_ep_am_short(ep, 0, 0, &data, sizeof(data));
            progress();
        } while ((status == UCS_ERR_NO_RESOURCE) &&
                 (ucs_get_time() < deadline));
        ASSERT_UCS_OK(status);

        while ((*count == before) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_EQ(before + 1, *count);
    }

    /* After every handshake has completed: both ifaces idle, no error
     * callback even after waiting well beyond the timeout */
    void check_steady_state()
    {
        check_iface_idle(m_e0);
        check_iface_idle(m_e1);
        EXPECT_EQ(0u, m_err_count);

        progress_for(3 * CONN_TIMEOUT_SEC);

        EXPECT_EQ(0u, m_err_count);
        check_iface_idle(m_e0);
        check_iface_idle(m_e1);
    }

    entity                *m_e0;
    entity                *m_e1;
    unsigned              m_err_count;
    bool                  m_has_conn_timeout;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<int>      m_raw_fds;
    volatile unsigned     m_am_count[2];
};

const double test_uct_tcp_explore_connect_disarm::CONN_TIMEOUT_SEC = 0.2;
const double test_uct_tcp_explore_connect_disarm::WAIT_TIMEOUT_SEC = 10.0;


/* The fixture must see the config knob on the PR branch: a sanity check that
 * the timeout really is 200ms there (skips on master) */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm, config_applied)
{
    std::string value;

    if (!m_has_conn_timeout) {
        UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
    }

    EXPECT_TRUE(get_config("CONN_TIMEOUT", value) ||
                get_config("TCP_CONN_TIMEOUT", value));
    UCS_TEST_MESSAGE << "TCP_CONN_TIMEOUT=" << value.c_str();
    EXPECT_TRUE(have_conn_timeout_fields);
}

/* (a) CONNECT_TO_IFACE one-sided: e0 -> e1. The connect side goes
 * CONNECTING -> WAITING_ACK -> CONNECTED (handle_conn_ack disarms), the
 * internal RX EP on e1 goes ACCEPTING -> CONNECTED (handle_conn_req disarms)
 * and stays alive in the UNEXP queue.
 * (c) Then e1 -> e0: the CONN_REQ already arrived before uct_ep_create(), so
 * uct_tcp_ep_connect() reuses the UNEXP RX EP (list:match_unexp ->
 * ep_list_reuse) and goes CONNECTING -> WAITING_ACK via replace_ep, the ACK
 * from e0's already connected EP disarms it. */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm,
           connect_to_iface_then_reuse_unexp)
{
    size_t fd_count = open_fd_count();

    uct_ep_h ep0 = create_ep_to_iface(m_e0, m_e1);
    /* blocking connect() + CONN_REQ sent: waiting for the ACK */
    check_armed_ep(ep0);
    EXPECT_EQ(1u, tcp_iface(m_e0)->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_e0->iface(), 0, NULL));

    wait_for_state(ep0, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(ep0);

    /* e1 has only the internal RX EP, connected, on the UNEXP queue (so not on
     * ep_list) */
    wait_for_ep_count(m_e1, 0);
    EXPECT_EQ(0u, ep_count_in_state(m_e1, UCT_TCP_EP_CONN_STATE_ACCEPTING));
    check_steady_state();
    send_recv_am(ep0, m_e1);

    /* (c) peer's CONN_REQ was received before this uct_ep_create() */
    uct_ep_h ep1 = create_ep_to_iface(m_e1, m_e0);
    /* the RX EP was reused: conn_retries counts the replace */
    EXPECT_EQ(1u, tcp_ep(ep1)->conn_retries);
    EXPECT_TRUE(tcp_ep(ep1)->flags & UCT_TCP_EP_FLAG_CTX_TYPE_RX);
    if (conn_state(ep1) != UCT_TCP_EP_CONN_STATE_CONNECTED) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep1));
        check_armed_ep(ep1);
        EXPECT_EQ(1u, tcp_iface(m_e1)->outstanding);
    }

    wait_for_state(ep1, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(ep1);
    check_connected_ep(ep0);
    /* the replaced internal EP is destroyed by the deferred one-shot */
    wait_for_ep_count(m_e1, 0);
    check_steady_state();

    send_recv_am(ep1, m_e0);
    send_recv_am(ep0, m_e1);
    EXPECT_EQ(0u, m_err_count);

    uct_ep_destroy(ep0);
    uct_ep_destroy(ep1);
    wait_for_ep_count(m_e0, 0);
    wait_for_ep_count(m_e1, 0);
    check_steady_state();
    wait_for_fd_count(fd_count);
}

/* (b) CONNECT_TO_EP, uct_ep_connect_to_ep_v2() on the accepting side first:
 * acceptor CLOSED -> ACCEPTING (armed), connector CLOSED -> CONNECTING ->
 * CONNECTED (conn_complete disarms, no ACK expected), then the CONN_REQ
 * reaches the acceptor: ACCEPTING -> CONNECTED via replace_ep (disarmed). */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm, connect_to_ep_acceptor_first)
{
    size_t fd_count = open_fd_count();
    entity *acc     = e0_accepts() ? m_e0 : m_e1;
    entity *con     = e0_accepts() ? m_e1 : m_e0;
    uct_ep_h acc_ep = create_c2e_ep(acc);
    uct_ep_h con_ep = create_c2e_ep(con);

    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(acc_ep));
    EXPECT_TRUE(ep_timeout_disarmed(tcp_ep(acc_ep)));

    connect_c2e(acc_ep, con_ep);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(acc_ep));
    check_armed_ep(acc_ep);
    EXPECT_EQ(1u, tcp_iface(acc)->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(acc->iface(), 0, NULL));

    connect_c2e(con_ep, acc_ep);
    /* blocking connect: CONN_REQ is sent and the EP is connected at once */
    wait_for_state(con_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(con_ep);

    wait_for_state(acc_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(acc_ep);
    EXPECT_FALSE(tcp_ep(acc_ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_FALSE(tcp_ep(con_ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    /* the internal EP which carried the CONN_REQ is gone */
    wait_for_ep_count(acc, 1);
    check_steady_state();

    send_recv_am(con_ep, acc);
    send_recv_am(acc_ep, con);
    EXPECT_EQ(0u, m_err_count);

    uct_ep_destroy(con_ep);
    uct_ep_destroy(acc_ep);
    check_steady_state();
    wait_for_fd_count(fd_count);
}

/* (b) CONNECT_TO_EP, uct_ep_connect_to_ep_v2() on the connecting side first
 * and the acceptor armed before the CONN_REQ is progressed: same transitions
 * in the other order. */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm, connect_to_ep_connector_first)
{
    size_t fd_count = open_fd_count();
    entity *acc     = e0_accepts() ? m_e0 : m_e1;
    entity *con     = e0_accepts() ? m_e1 : m_e0;
    uct_ep_h acc_ep = create_c2e_ep(acc);
    uct_ep_h con_ep = create_c2e_ep(con);

    connect_c2e(con_ep, acc_ep);
    wait_for_state(con_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(con_ep);
    EXPECT_EQ(0u, tcp_iface(con)->outstanding);

    /* no progress on the acceptor yet: the user EP is still CLOSED and on
     * the ptr map, nothing is armed on that iface */
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(acc_ep));
    EXPECT_TRUE(tcp_ep(acc_ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);

    connect_c2e(acc_ep, con_ep);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(acc_ep));
    check_armed_ep(acc_ep);
    EXPECT_EQ(1u, tcp_iface(acc)->outstanding);

    wait_for_state(acc_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(acc_ep);
    EXPECT_FALSE(tcp_ep(acc_ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    wait_for_ep_count(acc, 1);
    check_steady_state();

    send_recv_am(con_ep, acc);
    send_recv_am(acc_ep, con);
    EXPECT_EQ(0u, m_err_count);

    uct_ep_destroy(acc_ep);
    uct_ep_destroy(con_ep);
    check_steady_state();
    wait_for_fd_count(fd_count);
}

/* (b') CONNECT_TO_EP where the CONN_REQ is consumed before the acceptor calls
 * uct_ep_connect_to_ep_v2(): the acceptor's user EP goes CLOSED -> CONNECTED
 * directly (never armed) and connect_to_ep_v2 is a no-op on it. */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm, connect_to_ep_req_before_accept)
{
    size_t fd_count = open_fd_count();
    entity *acc     = e0_accepts() ? m_e0 : m_e1;
    entity *con     = e0_accepts() ? m_e1 : m_e0;
    uct_ep_h acc_ep = create_c2e_ep(acc);
    uct_ep_h con_ep = create_c2e_ep(con);

    connect_c2e(con_ep, acc_ep);
    wait_for_state(con_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);

    /* the CONN_REQ finds the user EP on the ptr map while it is CLOSED */
    wait_for_state(acc_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(acc_ep);
    EXPECT_FALSE(tcp_ep(acc_ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    wait_for_ep_count(acc, 1);
    check_steady_state();

    connect_c2e(acc_ep, con_ep);
    check_connected_ep(acc_ep);
    check_steady_state();

    send_recv_am(con_ep, acc);
    send_recv_am(acc_ep, con);
    EXPECT_EQ(0u, m_err_count);

    uct_ep_destroy(acc_ep);
    uct_ep_destroy(con_ep);
    check_steady_state();
    wait_for_fd_count(fd_count);
}

/* tmo:disarm_closed_destroy: an EP stuck in WAITING_ACK (peer accepts the
 * TCP connection but never answers CONN_REQ) is destroyed before the
 * deadline: nothing is tracked anymore and no error callback fires later.
 * No progress is called between create and destroy, so the sweep can not
 * run in between regardless of wall clock time. */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm,
           destroy_stalled_ep_before_deadline)
{
    struct sockaddr_storage listen_addr;

    if (!m_has_conn_timeout) {
        UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
    }

    raw_listener(&listen_addr);
    size_t fd_count = open_fd_count();
    uint16_t port   = port_of((struct sockaddr*)&listen_addr);
    uct_ep_h ep     = create_ep_to_port(m_e0, port);

    check_armed_ep(ep);
    EXPECT_EQ(1u, tcp_iface(m_e0)->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_e0->iface(), 0, NULL));

    uct_ep_destroy(ep);

    EXPECT_TRUE(iface_timeout_list_empty(tcp_iface(m_e0)));
    EXPECT_EQ(0u, tcp_iface(m_e0)->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_e0->iface(), 0, NULL));
    EXPECT_EQ(fd_count, open_fd_count());

    progress_for(3 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(0u, m_err_count);
    check_iface_idle(m_e0);
    check_iface_idle(m_e1);
}

/* Two stalled EPs, the first armed one is destroyed before the deadline:
 * the list stays consistent and only the surviving EP is reported, once. */
UCS_TEST_P(test_uct_tcp_explore_connect_disarm, destroy_one_of_two_stalled)
{
    struct sockaddr_storage listen_addr;

    if (!m_has_conn_timeout) {
        UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
    }

    raw_listener(&listen_addr);
    size_t fd_count = open_fd_count();
    uint16_t port   = port_of((struct sockaddr*)&listen_addr);
    uct_ep_h ep_a   = create_ep_to_port(m_e0, port);
    uct_ep_h ep_b   = create_ep_to_port(m_e0, port);

    check_armed_ep(ep_a);
    check_armed_ep(ep_b);
    EXPECT_EQ(2u, tcp_iface(m_e0)->outstanding);

    uct_ep_destroy(ep_a);
    EXPECT_EQ(1u, tcp_iface(m_e0)->outstanding);
    check_armed_ep(ep_b);

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(WAIT_TIMEOUT_SEC);
    while ((m_err_count == 0) && (ucs_get_time() < deadline)) {
        progress();
    }

    ASSERT_EQ(1u, m_err_count);
    EXPECT_EQ(ep_b, m_err_eps[0]);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep_b));
    EXPECT_EQ(0u, tcp_ep(ep_b)->events);
    EXPECT_TRUE(ep_timeout_disarmed(tcp_ep(ep_b)));
    EXPECT_TRUE(iface_timeout_list_empty(tcp_iface(m_e0)));
    EXPECT_EQ(0u, tcp_iface(m_e0)->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_e0->iface(), 0, NULL));

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);

    uct_ep_destroy(ep_b);
    EXPECT_EQ(fd_count, open_fd_count());
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_connect_disarm, tcp)
