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
 * Exploration tests for the simultaneous-connect path of the UCT TCP
 * transport: two CONNECT_TO_IFACE EPs whose CONN_REQs cross, fd ownership of
 * the accepted socket (ep->stale_fd), event set state of the involved EPs,
 * iface->outstanding accounting and the interplay with UCX_TCP_CONN_TIMEOUT.
 *
 * Peers are either a second uct_test entity which is progressed explicitly
 * or raw sockets which speak only the part of the UCT TCP handshake the test
 * wants, so no step depends on timing of a real peer. All wait loops are
 * bounded by WAIT_TIMEOUT_SEC and fail (rather than hang) when the expected
 * state is not reached.
 */
class test_uct_tcp_explore_simult : public uct_test {
public:
    test_uct_tcp_explore_simult() : m_err_count(0), m_err_status(UCS_OK)
    {
    }

    void init()
    {
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(0, err_handler));
        m_entities.push_back(uct_test::create_entity(0, err_handler));
    }

    void cleanup()
    {
        close_fds(m_raw_fds);
        uct_test::cleanup();
    }

protected:
    static const double WAIT_TIMEOUT_SEC;
    static const double CONN_TIMEOUT_SEC;

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_simult *self =
                reinterpret_cast<test_uct_tcp_explore_simult*>(arg);

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

    static uct_tcp_iface_t *tcp_iface(const entity &e)
    {
        return ucs_derived_of(e.iface(), uct_tcp_iface_t);
    }

    static const struct sockaddr *iface_addr(const entity &e)
    {
        return (const struct sockaddr*)&tcp_iface(e)->config.ifaddr;
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    static uint16_t port_of(const struct sockaddr *addr)
    {
        uint16_t port = 0;
        EXPECT_UCS_OK(ucs_sockaddr_get_port(addr, &port));
        return port;
    }

    /* Mirrors uct_tcp_cm_ep_accept_conn(): the side whose own address is
     * GREATER than the peer address adopts the accepted socket (and drops its
     * own connecting socket), the side whose address is SMALLER keeps its own
     * socket and parks the accepted one in ep->stale_fd */
    static bool adopts_accepted_fd(const struct sockaddr *local,
                                   const struct sockaddr *peer)
    {
        ucs_status_t status;
        int cmp = ucs_sockaddr_cmp(peer, local, &status);
        EXPECT_UCS_OK(status);
        return cmp < 0;
    }

    /* Listening socket on the iface IP which speaks only what the test
     * wants */
    int raw_listener(const entity &e, struct sockaddr_storage *addr)
    {
        socklen_t addr_len;
        size_t addr_size;
        int fd;

        memcpy(addr, iface_addr(e), sizeof(*addr));
        ASSERT_UCS_OK(ucs_sockaddr_set_port((struct sockaddr*)addr, 0));
        ASSERT_UCS_OK(ucs_sockaddr_sizeof((struct sockaddr*)addr, &addr_size));
        ASSERT_UCS_OK(ucs_socket_create(addr->ss_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);

        EXPECT_EQ(0, bind(fd, (struct sockaddr*)addr, addr_size));
        EXPECT_EQ(0, listen(fd, 16));
        ASSERT_UCS_OK(ucs_socket_getname(fd, addr, &addr_len));
        return fd;
    }

    /* Listener whose address compares greater than the iface address, so that
     * the iface EP connecting to it is the one which parks stale_fd */
    int raw_listener_greater(const entity &e, struct sockaddr_storage *addr)
    {
        for (int i = 0; i < 64; ++i) {
            int fd = raw_listener(e, addr);
            if (!adopts_accepted_fd(iface_addr(e), (struct sockaddr*)addr)) {
                return fd;
            }
            close(fd);
            m_raw_fds.pop_back();
        }
        UCS_TEST_SKIP_R("could not get a peer port greater than the iface port");
    }

    int raw_accept(int listen_fd)
    {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(listen_fd, (struct sockaddr*)&addr, &addr_len);
        EXPECT_GE(fd, 0) << strerror(errno);
        m_raw_fds.push_back(fd);
        return fd;
    }

    /* Non-blocking raw socket connected to the iface of @a e */
    int raw_connect(const entity &e)
    {
        int fd;

        ASSERT_UCS_OK(ucs_socket_create(iface_addr(e)->sa_family, SOCK_STREAM,
                                        0, &fd));
        m_raw_fds.push_back(fd);
        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));

        ucs_status_t status = ucs_socket_connect(fd, iface_addr(e));
        EXPECT_TRUE((status == UCS_OK) || (status == UCS_INPROGRESS));

        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!ucs_socket_is_connected(fd) && (ucs_get_time() < deadline)) {
            e.progress();
        }
        EXPECT_TRUE(ucs_socket_is_connected(fd));
        return fd;
    }

    void raw_send(int fd, const void *data, size_t length)
    {
        ASSERT_EQ((ssize_t)length, send(fd, data, length, MSG_NOSIGNAL))
                << strerror(errno);
    }

    void raw_recv(int fd, void *data, size_t length)
    {
        ASSERT_EQ((ssize_t)length, recv(fd, data, length, MSG_WAITALL))
                << strerror(errno);
    }

    /* Peer-visible state of a raw socket: UCS_ERR_NO_PROGRESS while the other
     * end is open and silent, UCS_ERR_NOT_CONNECTED once it has been closed */
    static ucs_status_t raw_peek(int fd)
    {
        char byte;
        ssize_t ret = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);

        if (ret > 0) {
            return UCS_OK;
        } else if (ret == 0) {
            return UCS_ERR_NOT_CONNECTED;
        } else if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return UCS_ERR_NO_PROGRESS;
        } else if (errno == ECONNRESET) {
            return UCS_ERR_CONNECTION_RESET;
        }
        return UCS_ERR_IO_ERROR;
    }

    void raw_send_magic_and_conn_req(const entity &e, int fd,
                                     const struct sockaddr *my_addr,
                                     ucs_conn_sn_t conn_sn)
    {
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;
        uct_tcp_am_hdr_t hdr;
        uct_tcp_cm_conn_req_pkt_t req;
        size_t sockaddr_len = tcp_iface(e)->config.sockaddr_len;
        std::vector<uint8_t> pkt;

        hdr.am_id       = UCT_TCP_EP_CM_AM_ID;
        hdr.length      = sizeof(req) + sockaddr_len;
        req.event       = UCT_TCP_CM_CONN_REQ;
        req.flags       = 0;
        req.cm_id.conn_sn = conn_sn;

        pkt.insert(pkt.end(), (uint8_t*)&magic, (uint8_t*)&magic + sizeof(magic));
        pkt.insert(pkt.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        pkt.insert(pkt.end(), (uint8_t*)&req, (uint8_t*)&req + sizeof(req));
        pkt.insert(pkt.end(), (uint8_t*)my_addr,
                   (uint8_t*)my_addr + sockaddr_len);
        raw_send(fd, &pkt[0], pkt.size());
    }

    void raw_send_conn_ack(int fd)
    {
        uct_tcp_am_hdr_t hdr;
        uct_tcp_cm_conn_event_t event = UCT_TCP_CM_CONN_ACK;
        std::vector<uint8_t> pkt;

        hdr.am_id  = UCT_TCP_EP_CM_AM_ID;
        hdr.length = sizeof(event);
        pkt.insert(pkt.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        pkt.insert(pkt.end(), (uint8_t*)&event,
                   (uint8_t*)&event + sizeof(event));
        raw_send(fd, &pkt[0], pkt.size());
    }

    /* Reads the CONN_REQ a connecting UCT TCP EP sends and checks it */
    void raw_recv_magic_and_conn_req(const entity &e, int fd,
                                     ucs_conn_sn_t exp_conn_sn)
    {
        uint64_t magic = 0;
        uct_tcp_am_hdr_t hdr;
        uct_tcp_cm_conn_req_pkt_t req;
        std::vector<uint8_t> addr(tcp_iface(e)->config.sockaddr_len);

        raw_recv(fd, &magic, sizeof(magic));
        EXPECT_EQ(UCT_TCP_MAGIC_NUMBER, magic);
        raw_recv(fd, &hdr, sizeof(hdr));
        EXPECT_EQ(UCT_TCP_EP_CM_AM_ID, hdr.am_id);
        EXPECT_EQ(sizeof(req) + addr.size(), hdr.length);
        raw_recv(fd, &req, sizeof(req));
        EXPECT_EQ(UCT_TCP_CM_CONN_REQ, req.event);
        EXPECT_EQ(exp_conn_sn, req.cm_id.conn_sn);
        raw_recv(fd, &addr[0], addr.size());
        EXPECT_EQ(port_of(iface_addr(e)), port_of((struct sockaddr*)&addr[0]));
    }

    /* CONNECT_TO_IFACE EP of @a e to a peer listening on @a port on the iface
     * IP (the device address is shared by all entities of the test) */
    uct_ep_h create_ep_to_port(const entity &e, uint16_t port)
    {
        std::vector<uint8_t> dev_addr(e.iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;
        uct_ep_h ep;

        ASSERT_UCS_OK(uct_iface_get_device_address(e.iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        iface_addr.port = htons(port);

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = e.iface();
        params.dev_addr   = (uct_device_addr_t*)&dev_addr[0];
        params.iface_addr = (uct_iface_addr_t*)&iface_addr;
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    std::string ep_list_dump(const entity &e)
    {
        uct_tcp_iface_t *iface = tcp_iface(e);
        std::stringstream ss;
        uct_tcp_ep_t *ep;

        UCS_ASYNC_BLOCK(iface->super.worker->async);
        ucs_list_for_each(ep, &iface->ep_list, list) {
            ss << "[ep " << ep << " state " << (int)ep->conn_state
               << " flags 0x" << std::hex << ep->flags << std::dec
               << " fd " << ep->fd << " stale_fd " << ep->stale_fd
               << " events " << ep->events << "] ";
        }
        UCS_ASYNC_UNBLOCK(iface->super.worker->async);
        return ss.str();
    }

    size_t ep_list_count(const entity &e)
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

    /* Progress @a e until @a cond() holds or the bounded wait expires */
    template <typename Cond>
    bool progress_until(const entity &e, const Cond &cond)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!cond() && (ucs_get_time() < deadline)) {
            e.progress();
        }
        return cond();
    }

    /* Progress every entity for @a sec seconds of wall clock, used only to
     * show that nothing else happens (callback does not refire) */
    void progress_all_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
            progress();
        }
    }

    struct state_is {
        state_is(uct_ep_h ep, uct_tcp_ep_conn_state_t state) :
            m_ep(ep), m_state(state) {}
        bool operator()() const { return conn_state(m_ep) == m_state; }
        uct_ep_h m_ep;
        uct_tcp_ep_conn_state_t m_state;
    };

    struct stale_fd_set {
        stale_fd_set(uct_ep_h ep) : m_ep(ep) {}
        bool operator()() const { return tcp_ep(m_ep)->stale_fd != -1; }
        uct_ep_h m_ep;
    };

    struct ep_list_has {
        ep_list_has(test_uct_tcp_explore_simult &test, const entity &e,
                    size_t count) : m_test(test), m_e(e), m_count(count) {}
        bool operator()() const { return m_test.ep_list_count(m_e) == m_count; }
        test_uct_tcp_explore_simult &m_test;
        const entity &m_e;
        size_t m_count;
    };

    struct fd_count_is {
        fd_count_is(size_t count) : m_count(count) {}
        bool operator()() const { return open_fd_count() == m_count; }
        size_t m_count;
    };

    struct err_count_is {
        err_count_is(const test_uct_tcp_explore_simult &test, unsigned count) :
            m_test(test), m_count(count) {}
        bool operator()() const { return m_test.m_err_count >= m_count; }
        const test_uct_tcp_explore_simult &m_test;
        unsigned m_count;
    };

    /* Waits until the async accept thread of @a e has created the internal
     * EP for the one incoming connection (fd accounting below depends on the
     * accepted socket already existing) */
    void wait_accepted(const entity &e)
    {
        ASSERT_TRUE(progress_until(e, ep_list_has(*this, e, 1)))
                << "no accepted EP on " << port_of(iface_addr(e));
    }

    void check_connected_ep(const entity &e, uct_ep_h ep)
    {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
        EXPECT_EQ(UCT_TCP_EP_FLAG_CTX_TYPE_TX | UCT_TCP_EP_FLAG_CTX_TYPE_RX,
                  tcp_ep(ep)->flags & UCT_TCP_EP_CTX_CAPS);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_NE(-1, tcp_ep(ep)->fd);
        EXPECT_TRUE(ucs_socket_is_connected(tcp_ep(ep)->fd));
        EXPECT_EQ(UCS_EVENT_SET_EVREAD, tcp_ep(ep)->events);
        EXPECT_EQ(0u, tcp_iface(e)->outstanding);
        EXPECT_EQ(0u, ep_list_count(e)) << "internal accept EP still alive: "
                                        << ep_list_dump(e);
        EXPECT_UCS_OK(uct_iface_flush(e.iface(), 0, NULL));
    }

    /* Destroys both user EPs and waits for the FIN exchange to tear down the
     * remaining RX-only EPs, so that the fd count returns to @a baseline */
    void destroy_and_check_baseline(const entity &a, uct_ep_h ep_a,
                                    const entity &b, uct_ep_h ep_b,
                                    size_t baseline)
    {
        uct_ep_destroy(ep_a);
        uct_ep_destroy(ep_b);

        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((open_fd_count() != baseline) && (ucs_get_time() < deadline)) {
            a.progress();
            b.progress();
        }
        EXPECT_EQ(baseline, open_fd_count()) << "fd leak after EP destroy";
        EXPECT_EQ(0u, tcp_iface(a)->outstanding);
        EXPECT_EQ(0u, tcp_iface(b)->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(a.iface(), 0, NULL));
        EXPECT_UCS_OK(uct_iface_flush(b.iface(), 0, NULL));
        EXPECT_EQ(0u, m_err_count);
    }

    /* Two entities on the same device, EPs created on both sides before any
     * progress: both EPs are WAITING_ACK and both CONN_REQs are in flight.
     * Returns the "small" entity (the one which parks stale_fd) in @a small
     * and the "great" entity (the one which adopts the accepted fd) in
     * @a great. */
    void setup_crossing_conn_reqs(const entity *&small, uct_ep_h &ep_small,
                                  const entity *&great, uct_ep_h &ep_great,
                                  size_t &baseline)
    {
        const entity &a = ent(0);
        const entity &b = ent(1);

        baseline = open_fd_count();

        uct_ep_h ep_a = create_ep_to_port(a, port_of(iface_addr(b)));
        uct_ep_h ep_b = create_ep_to_port(b, port_of(iface_addr(a)));

        /* CONN_NB is off by default: connect() completed synchronously and
         * the CONN_REQ was sent from within uct_ep_create */
        ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep_a));
        ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep_b));
        EXPECT_EQ(1u, tcp_iface(a)->outstanding);
        EXPECT_EQ(1u, tcp_iface(b)->outstanding);
        EXPECT_EQ(-1, tcp_ep(ep_a)->stale_fd);
        EXPECT_EQ(-1, tcp_ep(ep_b)->stale_fd);
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(a.iface(), 0, NULL));
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(b.iface(), 0, NULL));

        if (adopts_accepted_fd(iface_addr(a), iface_addr(b))) {
            great = &a; ep_great = ep_a;
            small = &b; ep_small = ep_b;
        } else {
            great = &b; ep_great = ep_b;
            small = &a; ep_small = ep_a;
        }
        ASSERT_TRUE(adopts_accepted_fd(iface_addr(*great), iface_addr(*small)));
        ASSERT_FALSE(adopts_accepted_fd(iface_addr(*small), iface_addr(*great)));

        /* The accept thread of each side creates one RECV_MAGIC_NUMBER EP */
        wait_accepted(a);
        wait_accepted(b);
        /* 2 connecting + 2 accepted sockets */
        EXPECT_EQ(baseline + 4, open_fd_count());
    }

    /* The side with the smaller address handles the crossing CONN_REQ while
     * its own EP is still WAITING_ACK: it keeps its own socket, parks the
     * accepted one in stale_fd and gets the RX capability */
    void check_stale_side_won(const entity &small, uct_ep_h ep_small,
                              size_t baseline)
    {
        ASSERT_TRUE(progress_until(small, stale_fd_set(ep_small)))
                << "stale_fd was never set (stale:set)";

        /* stale:set, ev:simult_win_accept_ep_cleared */
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep_small));
        EXPECT_EQ(UCT_TCP_EP_FLAG_CTX_TYPE_TX | UCT_TCP_EP_FLAG_CTX_TYPE_RX,
                  tcp_ep(ep_small)->flags & UCT_TCP_EP_CTX_CAPS);
        EXPECT_EQ(UCS_EVENT_SET_EVREAD, tcp_ep(ep_small)->events);
        EXPECT_NE(tcp_ep(ep_small)->fd, tcp_ep(ep_small)->stale_fd);
        /* the accepted EP gave up its fd (fd == -1) and was destroyed without
         * closing the socket: still 4 sockets, none on ep_list */
        EXPECT_TRUE(progress_until(small, ep_list_has(*this, small, 0)))
                << "accept EP not destroyed after handing over its fd";
        EXPECT_EQ(baseline + 4, open_fd_count());
        /* ACCEPTING++ then CLOSED-- of the accept EP: back to 1 */
        EXPECT_EQ(1u, tcp_iface(small)->outstanding);
        EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(small.iface(), 0, NULL));
    }

    unsigned              m_err_count;
    ucs_status_t          m_err_status;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<int>      m_raw_fds;
};

const double test_uct_tcp_explore_simult::WAIT_TIMEOUT_SEC = 10.0;
const double test_uct_tcp_explore_simult::CONN_TIMEOUT_SEC = 0.2;


/* Crossing CONN_REQs, the stale_fd side is progressed first, then the
 * adopting side, then the stale_fd side again until both are CONNECTED.
 * Transitions: stale:set, ev:simult_win_accept_ep_cleared,
 * conn:WAITING_ACK->CONNECTED_simult_lose, ev:transfer_simult_accept,
 * stale:close_on_ack */
UCS_TEST_P(test_uct_tcp_explore_simult, crossing_conn_req_stale_side_first)
{
    const entity *small, *great;
    uct_ep_h ep_small, ep_great;
    size_t baseline;

    setup_crossing_conn_reqs(small, ep_small, great, ep_great, baseline);
    check_stale_side_won(*small, ep_small, baseline);

    /* the adopting side did not progress yet */
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep_great));
    EXPECT_EQ(-1, tcp_ep(ep_great)->stale_fd);
    int great_fd_before = tcp_ep(ep_great)->fd;

    /* conn:WAITING_ACK->CONNECTED_simult_lose + ev:transfer_simult_accept:
     * the great side reads the crossing CONN_REQ, closes its own connecting
     * socket, adopts the accepted one and answers ACK|REQ on it */
    ASSERT_TRUE(progress_until(*great, state_is(ep_great,
                                                UCT_TCP_EP_CONN_STATE_CONNECTED)));
    EXPECT_NE(great_fd_before, tcp_ep(ep_great)->fd) << "accepted fd not adopted";
    check_connected_ep(*great, ep_great);
    /* its own connecting socket was closed: 3 sockets left */
    EXPECT_EQ(baseline + 3, open_fd_count());
    /* the small side is untouched so far */
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep_small));
    EXPECT_NE(-1, tcp_ep(ep_small)->stale_fd);

    /* stale:close_on_ack: ACK|REQ arrives on the small side's own socket */
    ASSERT_TRUE(progress_until(*small, state_is(ep_small,
                                                UCT_TCP_EP_CONN_STATE_CONNECTED)));
    check_connected_ep(*small, ep_small);
    EXPECT_EQ(baseline + 2, open_fd_count()) << "stale_fd not closed on ACK";
    EXPECT_EQ(0u, m_err_count);

    /* stale:close_on_cleanup is a no-op here (already -1), fd baseline */
    destroy_and_check_baseline(*small, ep_small, *great, ep_great, baseline);
}

/* Same crossing, but the adopting side is progressed first: it becomes
 * CONNECTED on the accepted socket and closes its own connecting socket while
 * the stale side has not yet looked at anything. The stale side then sees a
 * CONN_REQ on an accepted socket which the peer already closed, plus the
 * ACK|REQ on its own socket; whichever it reads first, it must end up
 * CONNECTED with stale_fd == -1 and without an error callback. */
UCS_TEST_P(test_uct_tcp_explore_simult, crossing_conn_req_adopting_side_first)
{
    const entity *small, *great;
    uct_ep_h ep_small, ep_great;
    size_t baseline;

    setup_crossing_conn_reqs(small, ep_small, great, ep_great, baseline);

    int great_fd_before = tcp_ep(ep_great)->fd;
    ASSERT_TRUE(progress_until(*great, state_is(ep_great,
                                                UCT_TCP_EP_CONN_STATE_CONNECTED)));
    EXPECT_NE(great_fd_before, tcp_ep(ep_great)->fd) << "accepted fd not adopted";
    check_connected_ep(*great, ep_great);
    EXPECT_EQ(baseline + 3, open_fd_count());
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep_small));
    EXPECT_EQ(-1, tcp_ep(ep_small)->stale_fd);

    ASSERT_TRUE(progress_until(*small, state_is(ep_small,
                                                UCT_TCP_EP_CONN_STATE_CONNECTED)));
    /* The small side may read the ACK|REQ on its own socket before the
     * CONN_REQ on the accepted socket (the accept EP is then still ACCEPTING
     * and counted in outstanding); once that CONN_REQ is read the accept EP
     * is destroyed together with its (redundant) socket. */
    ASSERT_TRUE(progress_until(*small, ep_list_has(*this, *small, 0)))
            << "accept EP not destroyed: " << ep_list_dump(*small);
    check_connected_ep(*small, ep_small);
    EXPECT_EQ(baseline + 2, open_fd_count())
            << "redundant accepted socket or stale_fd not closed";
    EXPECT_EQ(0u, m_err_count);

    destroy_and_check_baseline(*small, ep_small, *great, ep_great, baseline);
}

/* Raw peer with a greater address: it accepts the EP's connection, reads the
 * CONN_REQ, connects back and sends magic + CONN_REQ with the EP's conn_sn,
 * so the EP wins the simultaneous connect and parks the accepted socket in
 * stale_fd. The peer then ACKs on the first connection: the EP becomes
 * CONNECTED, the stale socket is closed (visible to the peer as EOF).
 * Transitions: stale:set, ev:simult_win_accept_ep_cleared,
 * stale:close_on_ack, stale:close_on_cleanup (fd of the user EP). */
UCS_TEST_P(test_uct_tcp_explore_simult, raw_peer_ack_closes_stale_fd)
{
    const entity &e = ent(0);
    struct sockaddr_storage peer_addr;
    size_t baseline;

    int listen_fd = raw_listener_greater(e, &peer_addr);
    baseline      = open_fd_count();

    uct_ep_h ep = create_ep_to_port(e, port_of((struct sockaddr*)&peer_addr));
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, tcp_iface(e)->outstanding);

    int acc_fd = raw_accept(listen_fd);
    raw_recv_magic_and_conn_req(e, acc_fd, 0);

    int conn_fd = raw_connect(e);
    wait_accepted(e);
    raw_send_magic_and_conn_req(e, conn_fd, (struct sockaddr*)&peer_addr, 0);

    /* stale:set */
    ASSERT_TRUE(progress_until(e, stale_fd_set(ep)))
            << "stale_fd never set, state " << conn_state(ep);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(UCT_TCP_EP_FLAG_CTX_TYPE_TX | UCT_TCP_EP_FLAG_CTX_TYPE_RX,
              tcp_ep(ep)->flags & UCT_TCP_EP_CTX_CAPS);
    EXPECT_EQ(UCS_EVENT_SET_EVREAD, tcp_ep(ep)->events);
    EXPECT_TRUE(progress_until(e, ep_list_has(*this, e, 0)));
    EXPECT_EQ(1u, tcp_iface(e)->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(e.iface(), 0, NULL));
    /* ep->fd + stale_fd + 2 raw sockets, nothing closed */
    EXPECT_EQ(baseline + 4, open_fd_count());
    EXPECT_EQ(UCS_ERR_NO_PROGRESS, raw_peek(conn_fd));

    /* stale:close_on_ack */
    raw_send_conn_ack(acc_fd);
    ASSERT_TRUE(progress_until(e, state_is(ep, UCT_TCP_EP_CONN_STATE_CONNECTED)));
    check_connected_ep(e, ep);
    EXPECT_EQ(baseline + 3, open_fd_count());
    EXPECT_EQ(UCS_ERR_NOT_CONNECTED, raw_peek(conn_fd))
            << "peer does not see stale_fd closed";
    EXPECT_EQ(UCS_ERR_NO_PROGRESS, raw_peek(acc_fd));
    EXPECT_EQ(0u, m_err_count);

    /* stale:close_on_cleanup (fd path): the EP sends FIN and stays RX-only
     * until the raw peer closes; closing the raw sockets then takes it down */
    uct_ep_destroy(ep);
    close_fds(m_raw_fds);
    ASSERT_TRUE(progress_until(e, fd_count_is(baseline - 1)))
            << "fd count " << open_fd_count() << " != " << (baseline - 1);
    EXPECT_EQ(0u, tcp_iface(e)->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(e.iface(), 0, NULL));
    EXPECT_EQ(0u, m_err_count);
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_simult, tcp)


/* Same fixture with a short UCX_TCP_CONN_TIMEOUT (PR only; skipped where the
 * config knob does not exist) */
class test_uct_tcp_explore_simult_timeout : public test_uct_tcp_explore_simult {
public:
    void init()
    {
        modify_config("TCP_CONN_TIMEOUT", "200ms", IGNORE_IF_NOT_EXIST);
        test_uct_tcp_explore_simult::init();
    }

protected:
    bool conn_timeout_supported(const entity &e)
    {
        uct_iface_config_t *config;
        char value[32];
        ucs_status_t status;

        EXPECT_UCS_OK(uct_md_iface_config_read(e.md(), GetParam()->tl_name.c_str(),
                                               NULL, NULL, &config));
        status = uct_config_get(config, "CONN_TIMEOUT", value, sizeof(value));
        uct_config_release(config);
        return status == UCS_OK;
    }
};

/* Raw peer with a greater address which makes the EP win the simultaneous
 * connect (stale_fd parked) but never ACKs: the EP must time out exactly
 * once, go CLOSED, drop outstanding to 0 and let the iface flush. Neither
 * ep->fd nor stale_fd are closed by the failure: the peer sees both
 * connections half-open until uct_ep_destroy (documented window), after
 * which the fd count is back at baseline.
 * Transitions: stale:set, stale:kept_open_after_timeout,
 * stale:close_on_cleanup */
UCS_TEST_P(test_uct_tcp_explore_simult_timeout, raw_peer_no_ack_timeout_keeps_stale_fd)
{
    const entity &e = ent(0);
    struct sockaddr_storage peer_addr;
    size_t baseline;

    if (!conn_timeout_supported(e)) {
        UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT config is not supported");
    }

    int listen_fd = raw_listener_greater(e, &peer_addr);
    baseline      = open_fd_count();

    uct_ep_h ep = create_ep_to_port(e, port_of((struct sockaddr*)&peer_addr));
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));

    int acc_fd = raw_accept(listen_fd);
    raw_recv_magic_and_conn_req(e, acc_fd, 0);
    int conn_fd = raw_connect(e);
    wait_accepted(e);
    raw_send_magic_and_conn_req(e, conn_fd, (struct sockaddr*)&peer_addr, 0);

    ASSERT_TRUE(progress_until(e, stale_fd_set(ep)))
            << "stale_fd never set, state " << conn_state(ep);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_TRUE(progress_until(e, ep_list_has(*this, e, 0)));
    EXPECT_EQ(1u, tcp_iface(e)->outstanding);
    EXPECT_EQ(baseline + 4, open_fd_count());
    int stale_fd = tcp_ep(ep)->stale_fd;
    int ep_fd    = tcp_ep(ep)->fd;

    /* never ACK: the handshake timeout must fire */
    {
        scoped_log_handler slh(wrap_errors_logger);
        ASSERT_TRUE(progress_until(e, err_count_is(*this, 1)))
                << "no timeout error callback, state " << conn_state(ep);
    }
    EXPECT_EQ(1u, m_err_count);
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    ASSERT_EQ(1u, m_err_eps.size());
    EXPECT_EQ(ep, m_err_eps[0]);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    EXPECT_EQ(0u, tcp_iface(e)->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(e.iface(), 0, NULL));
    /* uct_tcp_ep_set_failed moves the EP from conn_match_ctx to ep_list */
    EXPECT_EQ(1u, ep_list_count(e)) << ep_list_dump(e);

    /* stale:kept_open_after_timeout: nothing was closed by the failure */
    EXPECT_EQ(stale_fd, tcp_ep(ep)->stale_fd);
    EXPECT_EQ(ep_fd, tcp_ep(ep)->fd);
    EXPECT_EQ(baseline + 4, open_fd_count());
    EXPECT_EQ(UCS_ERR_NO_PROGRESS, raw_peek(conn_fd))
            << "peer of stale_fd already sees EOF";
    EXPECT_EQ(UCS_ERR_NO_PROGRESS, raw_peek(acc_fd))
            << "peer of ep->fd already sees EOF";

    /* a late ACK must not resurrect the EP and nothing refires */
    raw_send_conn_ack(acc_fd);
    progress_all_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(stale_fd, tcp_ep(ep)->stale_fd);

    /* stale:close_on_cleanup: uct_ep_destroy closes both sockets */
    uct_ep_destroy(ep);
    EXPECT_EQ(baseline + 2, open_fd_count()) << "fd/stale_fd not closed by destroy";
    EXPECT_EQ(UCS_ERR_NOT_CONNECTED, raw_peek(conn_fd));
    /* the late ACK was never read, so close() turns into a reset */
    ucs_status_t acc_status = raw_peek(acc_fd);
    EXPECT_TRUE((acc_status == UCS_ERR_NOT_CONNECTED) ||
                (acc_status == UCS_ERR_CONNECTION_RESET))
            << ucs_status_string(acc_status);
    close_fds(m_raw_fds);
    EXPECT_EQ(baseline - 1, open_fd_count());
    EXPECT_EQ(0u, tcp_iface(e)->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(e.iface(), 0, NULL));
    EXPECT_EQ(1u, m_err_count);
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_simult_timeout, tcp)
