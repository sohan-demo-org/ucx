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
#include <ucs/sys/sys.h>
}

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>


/**
 * Exploratory tests for the iface->outstanding counter of the UCT TCP
 * transport when healthy CONNECTED EPs with in-flight TX share an iface with
 * EPs whose handshake stalls (and, with UCX_TCP_CONN_TIMEOUT set, times out).
 *
 * Expected invariant at every checkpoint:
 *   iface->outstanding == #EPs in {CONNECTING, WAITING_ACK, ACCEPTING}
 *                       + sum of TX bytes still queued in ep->tx
 *                       + #EPs with UCT_TCP_EP_FLAG_PUT_TX_WAITING_ACK
 * and uct_iface_flush() returns UCS_INPROGRESS iff outstanding != 0.
 *
 * All peers are raw sockets or a second UCT entity which is progressed only
 * when the test decides to, so nothing depends on real network timing.
 */
class test_uct_tcp_explore_outstanding_mixed_flush : public uct_test {
public:
    test_uct_tcp_explore_outstanding_mixed_flush() :
        m_tcp_iface(NULL), m_sender(NULL), m_receiver(NULL), m_err_count(0),
        m_err_status(UCS_OK), m_am_count(0), m_comp_count(0)
    {
    }

    void init()
    {
        /* Small socket buffers so that a modest amount of AM traffic fills
         * the sender socket while the receiver is not progressed */
        modify_config("TCP_SNDBUF", "16kb");
        modify_config("TCP_RCVBUF", "16kb");
        modify_config("TCP_TX_SEG_SIZE", "8kb");
        modify_config("TCP_CONN_TIMEOUT", CONN_TIMEOUT_STR, IGNORE_IF_NOT_EXIST);
        uct_test::init();

        m_sender   = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_sender);
        m_receiver = uct_test::create_entity(0);
        m_entities.push_back(m_receiver);
        m_tcp_iface = ucs_derived_of(m_sender->iface(), uct_tcp_iface_t);

        ASSERT_UCS_OK(uct_iface_set_am_handler(m_receiver->iface(), AM_ID,
                                               am_handler, this, 0));
    }

    void cleanup()
    {
        for (size_t i = 0; i < m_eps.size(); ++i) {
            uct_ep_destroy(m_eps[i]);
        }
        m_eps.clear();
        close_fds(m_raw_fds);
        uct_test::cleanup();
    }

protected:
    static const uint8_t AM_ID = 17;
    static const char   *CONN_TIMEOUT_STR;
    static const double  CONN_TIMEOUT_SEC;
    static const double  WAIT_TIMEOUT_SEC;
    static const double  FILL_STALL_SEC;

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_outstanding_mixed_flush *self =
                reinterpret_cast<test_uct_tcp_explore_outstanding_mixed_flush*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_eps.push_back(ep);
        return UCS_OK;
    }

    static ucs_status_t am_handler(void *arg, void *data, size_t length,
                                   unsigned flags)
    {
        test_uct_tcp_explore_outstanding_mixed_flush *self =
                reinterpret_cast<test_uct_tcp_explore_outstanding_mixed_flush*>(arg);

        self->m_am_count++;
        return UCS_OK;
    }

    static void comp_cb(uct_completion_t *comp)
    {
        test_uct_tcp_explore_outstanding_mixed_flush *self =
                ucs_container_of(comp,
                                 test_uct_tcp_explore_outstanding_mixed_flush,
                                 m_comp);

        self->m_comp_count++;
    }

    static size_t pack_cb(void *dest, void *arg)
    {
        size_t length = *reinterpret_cast<size_t*>(arg);

        memset(dest, 0xab, length);
        return length;
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
        DIR *dir     = opendir("/proc/self/fd");
        size_t count = 0;

        EXPECT_TRUE(dir != NULL);
        while (readdir(dir) != NULL) {
            ++count;
        }
        closedir(dir);
        return count - 1; /* the directory stream itself */
    }

    /* Skips the test (UCS_TEST_SKIP_R) when the config knob does not exist,
     * i.e. without the UCX_TCP_CONN_TIMEOUT feature */
    void skip_without_conn_timeout()
    {
        modify_config("TCP_CONN_TIMEOUT", CONN_TIMEOUT_STR, SKIP_IF_NOT_EXIST);
    }

    const struct sockaddr *iface_addr() const
    {
        return (const struct sockaddr*)&m_tcp_iface->config.ifaddr;
    }

    /* Listening socket on the iface IP address which never speaks the UCT
     * TCP protocol, so every EP connected to it stalls in WAITING_ACK */
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

    /* Blocking raw socket connected to @a addr */
    int raw_connect(const struct sockaddr *addr)
    {
        int fd;

        ASSERT_UCS_OK(ucs_socket_create(addr->sa_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);
        ASSERT_UCS_OK(ucs_socket_connect(fd, addr));
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
        std::vector<uint8_t> dev_addr(m_sender->iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;
        uct_ep_h ep;

        ASSERT_UCS_OK(uct_iface_get_device_address(m_sender->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        iface_addr.port   = htons(port);
        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = m_sender->iface();
        params.dev_addr   = (uct_device_addr_t*)&dev_addr[0];
        params.iface_addr = (uct_iface_addr_t*)&iface_addr;
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        m_eps.push_back(ep);
        return ep;
    }

    /* Not yet connected CONNECT_TO_EP EP (CLOSED, on the ptr map) */
    uct_ep_h create_connect_to_ep_ep()
    {
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = m_sender->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        m_eps.push_back(ep);
        return ep;
    }

    /* Healthy CONNECT_TO_IFACE EP from the sender to the receiver entity */
    uct_ep_h create_healthy_ep()
    {
        size_t index = m_sender->num_eps();

        m_sender->connect_to_iface(index, *m_receiver);
        uct_ep_h ep = m_sender->ep(index);

        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((conn_state(ep) != UCT_TCP_EP_CONN_STATE_CONNECTED) &&
               (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
        return ep;
    }

    void destroy_ep(uct_ep_h ep)
    {
        std::vector<uct_ep_h>::iterator it = std::find(m_eps.begin(),
                                                       m_eps.end(), ep);
        ASSERT_TRUE(it != m_eps.end());
        m_eps.erase(it);
        uct_ep_destroy(ep);
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    static bool conn_in_progress(uct_tcp_ep_t *ep)
    {
        return (ep->conn_state == UCT_TCP_EP_CONN_STATE_CONNECTING) ||
               (ep->conn_state == UCT_TCP_EP_CONN_STATE_WAITING_ACK) ||
               (ep->conn_state == UCT_TCP_EP_CONN_STATE_ACCEPTING);
    }

    static size_t tx_queued(uct_ep_h ep)
    {
        return tcp_ep(ep)->tx.length - tcp_ep(ep)->tx.offset;
    }

    static bool put_waiting_ack(uct_ep_h ep)
    {
        return tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_PUT_TX_WAITING_ACK;
    }

    static size_t ep_outstanding(uct_tcp_ep_t *ep)
    {
        return (conn_in_progress(ep) ? 1 : 0) + (ep->tx.length - ep->tx.offset) +
               ((ep->flags & UCT_TCP_EP_FLAG_PUT_TX_WAITING_ACK) ? 1 : 0);
    }

    /* The sum formula over all EPs of the sender iface: EPs on ep_list
     * (including internal ones) plus the user EPs that moved to the
     * connection matching context */
    size_t expected_outstanding()
    {
        size_t sum = 0;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(m_tcp_iface->super.worker->async);
        ucs_list_for_each(ep, &m_tcp_iface->ep_list, list) {
            sum += ep_outstanding(ep);
        }
        UCS_ASYNC_UNBLOCK(m_tcp_iface->super.worker->async);

        for (size_t i = 0; i < m_sender->num_eps(); ++i) {
            uct_ep_h ep = m_sender->ep(i); /* NULL after destroy_ep(i) */
            if ((ep != NULL) &&
                (tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_MATCH_CTX)) {
                sum += ep_outstanding(tcp_ep(ep));
            }
        }
        for (size_t i = 0; i < m_eps.size(); ++i) {
            if (tcp_ep(m_eps[i])->flags & UCT_TCP_EP_FLAG_ON_MATCH_CTX) {
                sum += ep_outstanding(tcp_ep(m_eps[i]));
            }
        }
        return sum;
    }

    void check_outstanding(size_t expected, const char *checkpoint)
    {
        size_t outstanding = m_tcp_iface->outstanding;

        EXPECT_EQ(expected, outstanding) << checkpoint;
        EXPECT_EQ(expected_outstanding(), outstanding) << checkpoint;
        EXPECT_EQ((outstanding != 0) ? UCS_INPROGRESS : UCS_OK,
                  uct_iface_flush(m_sender->iface(), 0, NULL)) << checkpoint;
    }

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

    void wait_for_err(unsigned count, bool sender_only)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((m_err_count < count) && (ucs_get_time() < deadline)) {
            if (sender_only) {
                m_sender->progress();
            } else {
                progress();
            }
        }
    }

    /* Progress the sender only, until @a done or the deadline is reached */
    template <typename Pred> void sender_progress_until(Pred done)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!done() && (ucs_get_time() < deadline)) {
            m_sender->progress();
        }
    }

    bool sender_drained(uct_ep_h ep)
    {
        return (tx_queued(ep) == 0) && !put_waiting_ack(ep);
    }

    /* Post a 1kb PUT zcopy on @a ep towards @a recvbuf; the receiver is not
     * progressed so the EP stays in PUT_TX_WAITING_ACK */
    void post_put_waiting_ack(uct_ep_h ep, mapped_buffer &sendbuf,
                              mapped_buffer &recvbuf)
    {
        UCS_TEST_GET_BUFFER_IOV(iov, iovcnt, sendbuf.ptr(), sendbuf.length(),
                                sendbuf.memh(), 1);

        m_comp.func   = comp_cb;
        m_comp.count  = 1;
        m_comp.status = UCS_OK;

        ASSERT_EQ(UCS_INPROGRESS,
                  uct_ep_put_zcopy(ep, iov, iovcnt, recvbuf.addr(),
                                   recvbuf.rkey(), &m_comp));
        /* the PUT request is small, so it went fully to the socket */
        EXPECT_EQ(0u, tx_queued(ep));
        EXPECT_TRUE(put_waiting_ack(ep));
    }

    /* Send AM bcopy messages while progressing the sender only, until the
     * socket (SNDBUF + peer RCVBUF) is full for good: the receiver never
     * reads, so once no byte could be pushed for FILL_STALL_SEC the queued
     * TX bytes cannot drain anymore without receiver progress */
    size_t fill_tx(uct_ep_h ep)
    {
        const size_t limit = 4 * UCS_MBYTE;
        size_t length = m_tcp_iface->config.tx_seg_size - sizeof(uct_tcp_am_hdr_t);
        size_t total  = 0;
        ucs_time_t stall_deadline = 0;
        ssize_t packed;

        while (total < limit) {
            packed = uct_ep_am_bcopy(ep, AM_ID, pack_cb, &length, 0);
            if (packed == UCS_ERR_NO_RESOURCE) {
                if (stall_deadline == 0) {
                    stall_deadline = ucs_get_time() +
                                     ucs_time_from_sec(FILL_STALL_SEC);
                } else if (ucs_get_time() > stall_deadline) {
                    break;
                }
                m_sender->progress();
                continue;
            }

            EXPECT_EQ((ssize_t)length, packed);
            if (packed != (ssize_t)length) {
                break;
            }
            stall_deadline = 0;
            total         += packed;
            ++m_am_sent;
        }

        EXPECT_LT(total, limit) << "socket never became full";
        EXPECT_LT(0u, tx_queued(ep)) << "no TX bytes are queued";
        UCS_TEST_MESSAGE << m_am_sent << " AMs sent, " << tx_queued(ep)
                         << " bytes queued";
        return tx_queued(ep);
    }

    uct_tcp_iface_t       *m_tcp_iface;
    entity                *m_sender;
    entity                *m_receiver;
    std::vector<int>       m_raw_fds;
    std::vector<uct_ep_h>  m_eps;
    std::vector<uct_ep_h>  m_err_eps;
    unsigned               m_err_count;
    ucs_status_t           m_err_status;
    unsigned               m_am_count;
    unsigned               m_am_sent;
    unsigned               m_comp_count;
    uct_completion_t       m_comp;
};

const uint8_t test_uct_tcp_explore_outstanding_mixed_flush::AM_ID;
const char  *test_uct_tcp_explore_outstanding_mixed_flush::CONN_TIMEOUT_STR = "200ms";
const double test_uct_tcp_explore_outstanding_mixed_flush::CONN_TIMEOUT_SEC = 0.2;
const double test_uct_tcp_explore_outstanding_mixed_flush::WAIT_TIMEOUT_SEC = 30.0;
const double test_uct_tcp_explore_outstanding_mixed_flush::FILL_STALL_SEC   = 1.0;


/* Three EPs stall in WAITING_ACK while a healthy EP has a PUT waiting for
 * its ACK and a socket full of AM bcopy data. After the stalled EPs time
 * out, outstanding must still hold the healthy TX and uct_iface_flush must
 * stay UCS_INPROGRESS until the receiver drains it. */
UCS_TEST_P(test_uct_tcp_explore_outstanding_mixed_flush,
           mixed_inflight_tx_and_stalled_timeouts)
{
    const unsigned num_stalled = 3;
    struct sockaddr_storage listen_addr;
    std::vector<uct_ep_h> stalled;
    size_t fd_count, queued;

    skip_without_conn_timeout();
    m_am_sent = 0;

    uct_ep_h healthy = create_healthy_ep();
    check_outstanding(0, "after healthy connect");

    mapped_buffer sendbuf(1024, 0x1234, *m_sender);
    mapped_buffer recvbuf(1024, 0, *m_receiver);

    /* Healthy TX first: the PUT waits for an ACK and the AM bytes stay
     * queued for as long as the receiver is not progressed */
    post_put_waiting_ack(healthy, sendbuf, recvbuf);
    check_outstanding(1, "PUT waiting for ACK");

    queued = fill_tx(healthy);
    check_outstanding(1 + queued, "AM TX queued");
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, uct_ep_flush(healthy, 0, NULL));

    raw_listener(&listen_addr);
    fd_count = open_fd_count();
    for (unsigned i = 0; i < num_stalled; ++i) {
        stalled.push_back(create_ep_to_port(port_of((struct sockaddr*)&listen_addr)));
    }
    EXPECT_EQ(fd_count + num_stalled, open_fd_count());

    /* CONN_REQ is written by the sender progress; the raw listener never
     * answers */
    sender_progress_until([&]() {
        for (unsigned i = 0; i < num_stalled; ++i) {
            if (conn_state(stalled[i]) != UCT_TCP_EP_CONN_STATE_WAITING_ACK) {
                return false;
            }
        }
        return true;
    });
    for (unsigned i = 0; i < num_stalled; ++i) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(stalled[i]));
        EXPECT_EQ(-1, tcp_ep(stalled[i])->stale_fd);
    }
    EXPECT_EQ(0u, m_err_count);
    check_outstanding(num_stalled + 1 + queued, "stalled EPs in WAITING_ACK");

    /* Let the stalled EPs time out; only the sender is progressed, so the
     * healthy TX cannot drain meanwhile */
    wait_for_err(num_stalled, true);
    ASSERT_EQ(num_stalled, m_err_count);
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    for (unsigned i = 0; i < num_stalled; ++i) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(stalled[i]));
        EXPECT_EQ(0u, tcp_ep(stalled[i])->events);
        EXPECT_EQ(0u, tx_queued(stalled[i]));
        EXPECT_TRUE(std::find(m_err_eps.begin(), m_err_eps.end(),
                              stalled[i]) != m_err_eps.end());
    }
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(healthy));
    EXPECT_TRUE(put_waiting_ack(healthy));
    EXPECT_EQ(queued, tx_queued(healthy));
    check_outstanding(1 + queued, "after timeouts, healthy TX still queued");
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, uct_ep_flush(healthy, 0, NULL));

    /* Now drain: progress both sides */
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!sender_drained(healthy) && (ucs_get_time() < deadline)) {
            progress();
        }
    }
    EXPECT_TRUE(sender_drained(healthy));
    EXPECT_EQ(1u, m_comp_count);
    check_outstanding(0, "healthy TX drained");
    EXPECT_EQ(num_stalled, m_err_count);

    /* EP flush after AMs posts a zero-length PUT (NEED_FLUSH) and completes
     * once its ACK is back */
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        ucs_status_t status;
        do {
            status = uct_ep_flush(healthy, 0, NULL);
            progress();
        } while ((status == UCS_INPROGRESS) && (ucs_get_time() < deadline));
        EXPECT_EQ(UCS_OK, status);
    }
    check_outstanding(0, "healthy EP flushed");

    /* all AMs reach the receiver */
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((m_am_count < m_am_sent) && (ucs_get_time() < deadline)) {
            progress();
        }
    }
    EXPECT_EQ(m_am_sent, m_am_count);
    recvbuf.pattern_check(0x1234);

    for (unsigned i = 0; i < num_stalled; ++i) {
        destroy_ep(stalled[i]);
    }
    EXPECT_EQ(fd_count, open_fd_count());
    check_outstanding(0, "stalled EPs destroyed");
    EXPECT_EQ(num_stalled, m_err_count);
}

/* TX posted on an EP stuck in WAITING_ACK is rejected with NO_RESOURCE and
 * must not be accounted in outstanding; the timeout then fails the EP and
 * leaves a clean counter */
UCS_TEST_P(test_uct_tcp_explore_outstanding_mixed_flush,
           tx_on_waiting_ack_ep_not_counted)
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;
    size_t length;

    skip_without_conn_timeout();

    mapped_buffer sendbuf(1024, 0x1234, *m_sender);
    mapped_buffer recvbuf(1024, 0, *m_receiver);
    UCS_TEST_GET_BUFFER_IOV(iov, iovcnt, sendbuf.ptr(), sendbuf.length(),
                            sendbuf.memh(), 1);

    raw_listener(&listen_addr);
    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));

    sender_progress_until([&]() {
        return conn_state(ep) == UCT_TCP_EP_CONN_STATE_WAITING_ACK;
    });
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    check_outstanding(1, "WAITING_ACK");

    length = 64;
    EXPECT_EQ((ssize_t)UCS_ERR_NO_RESOURCE,
              uct_ep_am_bcopy(ep, AM_ID, pack_cb, &length, 0));
    m_comp.func   = comp_cb;
    m_comp.count  = 1;
    m_comp.status = UCS_OK;
    EXPECT_EQ(UCS_ERR_NO_RESOURCE,
              uct_ep_put_zcopy(ep, iov, iovcnt, recvbuf.addr(), recvbuf.rkey(),
                               &m_comp));
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, uct_ep_flush(ep, 0, NULL));
    EXPECT_EQ(0u, tx_queued(ep));
    EXPECT_FALSE(put_waiting_ack(ep));
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    check_outstanding(1, "WAITING_ACK after rejected TX");

    wait_for_err(1, true);
    ASSERT_EQ(1u, m_err_count);
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    EXPECT_EQ(ep, m_err_eps[0]);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
    check_outstanding(0, "timed out");

    /* TX on a failed EP is rejected without touching the counter */
    EXPECT_EQ((ssize_t)UCS_ERR_CONNECTION_RESET,
              uct_ep_am_bcopy(ep, AM_ID, pack_cb, &length, 0));
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET,
              uct_ep_put_zcopy(ep, iov, iovcnt, recvbuf.addr(), recvbuf.rkey(),
                               &m_comp));
    EXPECT_EQ(0u, m_comp_count);
    check_outstanding(0, "TX on failed EP");

    /* a few more sweeps must not report the EP again */
    for (unsigned i = 0; i < 100; ++i) {
        m_sender->progress();
    }
    EXPECT_EQ(1u, m_err_count);

    destroy_ep(ep);
    EXPECT_EQ(fd_count, open_fd_count());
    check_outstanding(0, "destroyed");
}

/* A CONNECT_TO_EP EP receives the peer CONN_REQ before uct_ep_connect_to_ep
 * is called: CLOSED->CONNECTED must not decrement outstanding (there was no
 * matching increment); the internal accepting EP's ACCEPTING increment is
 * returned when it is dropped. Afterwards TX to the raw peer is accounted
 * and drained normally. Runs with and without the timeout config. */
UCS_TEST_P(test_uct_tcp_explore_outstanding_mixed_flush,
           connect_to_ep_early_conn_req_no_decrement)
{
    struct sockaddr_storage peer_addr;
    size_t sockaddr_len, length;
    uint16_t port;

    /* the peer address must compare lower than the iface address so that
     * the local side is the accepting one */
    memcpy(&peer_addr, iface_addr(), sizeof(peer_addr));
    port = port_of(iface_addr());
    if (port <= 1) {
        UCS_TEST_SKIP_R("iface port is too low to build a lower peer address");
    }
    ASSERT_UCS_OK(ucs_sockaddr_set_port((struct sockaddr*)&peer_addr, port - 1));
    ASSERT_UCS_OK(ucs_sockaddr_sizeof((struct sockaddr*)&peer_addr,
                                      &sockaddr_len));

    size_t fd_count = open_fd_count();
    uct_ep_h ep     = create_connect_to_ep_ep();
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONNECT_TO_EP);
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_EQ(1u, ep_count());
    check_outstanding(0, "CONNECT_TO_EP EP created");

    /* Raw peer: magic number + CONN_REQ(CONNECT_TO_EP, our ptr map key) in
     * one write, so the internal EP goes RECV_MAGIC_NUMBER -> ACCEPTING ->
     * dropped and the user EP CLOSED -> CONNECTED without any timing gap */
    std::vector<uint8_t> pkt(sizeof(uint64_t) + sizeof(uct_tcp_am_hdr_t) +
                             sizeof(uct_tcp_cm_conn_req_pkt_t) + sockaddr_len);
    uint8_t *p = &pkt[0];
    *(uint64_t*)p = UCT_TCP_MAGIC_NUMBER;
    p += sizeof(uint64_t);
    uct_tcp_am_hdr_t *hdr = (uct_tcp_am_hdr_t*)p;
    hdr->am_id  = UCT_TCP_EP_CM_AM_ID;
    hdr->length = sizeof(uct_tcp_cm_conn_req_pkt_t) + sockaddr_len;
    p += sizeof(*hdr);
    uct_tcp_cm_conn_req_pkt_t *req = (uct_tcp_cm_conn_req_pkt_t*)p;
    req->event = UCT_TCP_CM_CONN_REQ;
    req->flags = UCT_TCP_CM_CONN_REQ_PKT_FLAG_CONNECT_TO_EP;
    req->cm_id.ptr_map_key = tcp_ep(ep)->cm_id.ptr_map_key;
    memcpy(req + 1, &peer_addr, sockaddr_len);

    int peer_fd = raw_connect(iface_addr());
    ASSERT_UCS_OK(ucs_socket_send(peer_fd, &pkt[0], pkt.size()));

    sender_progress_until([&]() {
        return (conn_state(ep) == UCT_TCP_EP_CONN_STATE_CONNECTED) &&
               (ep_count() == 1);
    });
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
    EXPECT_EQ(1u, ep_count()) << "internal accepting EP was not dropped";
    EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
    EXPECT_EQ(0u, m_err_count);
    check_outstanding(0, "early CONN_REQ: CLOSED->CONNECTED");
    EXPECT_EQ(fd_count + 2, open_fd_count()); /* raw peer + accepted fd */

    /* late uct_ep_connect_to_ep on the already connected EP is a no-op */
    {
        std::vector<uint8_t> dev_addr(m_sender->iface_attr().device_addr_len);
        uct_tcp_ep_addr_t peer_ep_addr;

        ASSERT_UCS_OK(uct_iface_get_device_address(m_sender->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        peer_ep_addr.iface_addr.port = htons(port - 1);
        peer_ep_addr.ptr_map_key     = 0xdead;
        EXPECT_EQ(UCS_OK, uct_ep_connect_to_ep(ep, (uct_device_addr_t*)&dev_addr[0],
                                               (uct_ep_addr_t*)&peer_ep_addr));
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
        check_outstanding(0, "late connect_to_ep");
    }

    /* TX bytes to the raw peer are accounted and drained. uct_ep_flush is
     * deliberately not called here: an AM sets NEED_FLUSH, so the EP flush
     * would post a zero-length PUT the raw peer never acknowledges (see
     * destroy_ep_with_put_waiting_ack) */
    length = 256;
    EXPECT_EQ((ssize_t)length, uct_ep_am_bcopy(ep, AM_ID, pack_cb, &length, 0));
    sender_progress_until([&]() { return tx_queued(ep) == 0; });
    check_outstanding(0, "AM to raw peer drained");
    EXPECT_FALSE(put_waiting_ack(ep));

    std::vector<uint8_t> rx(sizeof(uct_tcp_am_hdr_t) + length);
    ASSERT_UCS_OK(ucs_socket_recv(peer_fd, &rx[0], rx.size()));
    EXPECT_EQ(AM_ID, ((uct_tcp_am_hdr_t*)&rx[0])->am_id);
    EXPECT_EQ(length, ((uct_tcp_am_hdr_t*)&rx[0])->length);

    EXPECT_EQ(0u, m_err_count);
    destroy_ep(ep);
    check_outstanding(0, "destroyed");
    EXPECT_EQ(fd_count + 1, open_fd_count()); /* only the raw peer is left */
}

/* Destroying a CONNECTED EP whose PUT is still waiting for the ACK must
 * return the PUT_TX_WAITING_ACK unit of iface->outstanding, otherwise
 * uct_iface_flush never completes again on this iface. The receiver is not
 * progressed, so the ACK deterministically never arrives before destroy.
 * Does not need the timeout config. */
UCS_TEST_P(test_uct_tcp_explore_outstanding_mixed_flush,
           destroy_ep_with_put_waiting_ack)
{
    uct_ep_h healthy = create_healthy_ep();
    size_t fd_count  = open_fd_count();
    check_outstanding(0, "after healthy connect");

    mapped_buffer sendbuf(1024, 0x1234, *m_sender);
    mapped_buffer recvbuf(1024, 0, *m_receiver);

    post_put_waiting_ack(healthy, sendbuf, recvbuf);
    check_outstanding(1, "PUT waiting for ACK");
    EXPECT_EQ(UCS_INPROGRESS, uct_ep_flush(healthy, 0, NULL));

    m_sender->destroy_ep(0);
    EXPECT_EQ(1u, m_comp_count) << "PUT completion not purged on destroy";
    EXPECT_EQ(0u, ep_count());
    check_outstanding(0, "EP with PUT_TX_WAITING_ACK destroyed");
    EXPECT_EQ(fd_count - 1, open_fd_count());

    /* the receiver may now consume the PUT and fail on the closed socket */
    {
        scoped_log_handler slh(wrap_errors_logger);
        for (unsigned i = 0; i < 100; ++i) {
            progress();
        }
    }
    recvbuf.pattern_check(0x1234);
    check_outstanding(0, "after receiver progress");
    EXPECT_EQ(0u, m_err_count);
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_outstanding_mixed_flush, tcp)
