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
 * Tests for UCX_TCP_CONN_TIMEOUT: an EP which is stuck in a connection
 * establishment state (CONNECTING / WAITING_ACK / ACCEPTING) must be failed
 * with UCS_ERR_ENDPOINT_TIMEOUT. The peers in these tests are raw sockets
 * which deliberately never complete the UCT TCP handshake, so the tests do
 * not depend on timing of a real peer.
 */
class test_uct_tcp_conn_timeout : public uct_test {
public:
    test_uct_tcp_conn_timeout() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_err_cb_fd(-1)
    {
    }

    void init()
    {
        uct_test::init();
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
    static const size_t CONN_ACK_PKT_PREREAD;

    /* The error callback optionally writes raw bytes into a peer socket:
     * this puts data on the wire from inside uct_worker_progress(), after
     * the iface polled its event set and failed the EP, but before the
     * one-shot callbacks of the worker progress queue run */
    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_conn_timeout *self =
                reinterpret_cast<test_uct_tcp_conn_timeout*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_eps.push_back(ep);

        if ((self->m_err_cb_fd != -1) && !self->m_err_cb_data.empty()) {
            EXPECT_UCS_OK(ucs_socket_send(self->m_err_cb_fd,
                                          &self->m_err_cb_data[0],
                                          self->m_err_cb_data.size()));
            self->m_err_cb_data.clear();
        }
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

    /* Receive exactly @a length bytes from a raw socket, progressing the
     * iface while waiting */
    std::vector<uint8_t> raw_recv(int fd, size_t length)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        std::vector<uint8_t> data(length);
        size_t offset = 0;
        size_t chunk;
        ucs_status_t status;

        while ((offset < length) && (ucs_get_time() < deadline)) {
            chunk  = length - offset;
            status = ucs_socket_recv_nb(fd, &data[offset], 0, &chunk);
            if (status == UCS_OK) {
                offset += chunk;
            } else if (status == UCS_ERR_NO_PROGRESS) {
                progress();
            } else {
                ADD_FAILURE() << "recv failed: " << ucs_status_string(status);
                break;
            }
        }
        EXPECT_EQ(length, offset);
        return data;
    }

    static void append(std::vector<uint8_t> &pkt, const void *data,
                       size_t length)
    {
        pkt.insert(pkt.end(), (const uint8_t*)data,
                   (const uint8_t*)data + length);
    }

    static void append_am_hdr(std::vector<uint8_t> &pkt, size_t length)
    {
        uct_tcp_am_hdr_t hdr;

        hdr.am_id  = UCT_TCP_EP_CM_AM_ID;
        hdr.length = length;
        append(pkt, &hdr, sizeof(hdr));
    }

    /* CONN_REQ as sent by a connecting peer: magic + AM hdr + req + addr */
    std::vector<uint8_t> conn_req_pkt(const struct sockaddr *peer_addr)
    {
        std::vector<uint8_t> pkt;
        uct_tcp_cm_conn_req_pkt_t req;
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;

        append(pkt, &magic, sizeof(magic));
        append_am_hdr(pkt, sizeof(req) + m_tcp_iface->config.sockaddr_len);
        req.event         = UCT_TCP_CM_CONN_REQ;
        req.flags         = 0;
        req.cm_id.conn_sn = 0;
        append(pkt, &req, sizeof(req));
        append(pkt, peer_addr, m_tcp_iface->config.sockaddr_len);
        return pkt;
    }

    static std::vector<uint8_t> conn_ack_pkt()
    {
        std::vector<uint8_t> pkt;
        uint32_t event = UCT_TCP_CM_CONN_ACK;

        append_am_hdr(pkt, sizeof(event));
        append(pkt, &event, sizeof(event));
        return pkt;
    }

    /* Peer which connects to the iface and sends magic + CONN_REQ (claiming
     * the address @a peer_addr) followed by the first CONN_ACK_PKT_PREREAD
     * bytes of a CONN_ACK. The iface creates an internal RX-only EP which
     * becomes CONNECTED, is kept on the connection matching context and
     * holds the partial CONN_ACK in its RX buffer. Returns the peer socket,
     * the remaining CONN_ACK bytes are returned in @a ack_rest */
    int preread_peer(const struct sockaddr *peer_addr,
                     std::vector<uint8_t> &ack_rest)
    {
        std::vector<uint8_t> ack = conn_ack_pkt();
        std::vector<uint8_t> pkt = conn_req_pkt(peer_addr);

        EXPECT_TRUE(CONN_ACK_PKT_PREREAD < sizeof(uct_tcp_am_hdr_t));

        int fd = raw_connect(iface_addr());
        while (!ucs_socket_is_connected(fd)) {
            progress();
        }

        append(pkt, &ack[0], CONN_ACK_PKT_PREREAD);
        ASSERT_UCS_OK(ucs_socket_send(fd, &pkt[0], pkt.size()));

        /* the internal EP replies with CONN_ACK once it is CONNECTED */
        std::vector<uint8_t> reply = raw_recv(fd, ack.size());
        EXPECT_EQ(ack, reply);

        ack_rest.assign(ack.begin() + CONN_ACK_PKT_PREREAD, ack.end());
        return fd;
    }

    uint16_t port_of(const struct sockaddr *addr)
    {
        uint16_t port = 0;
        EXPECT_UCS_OK(ucs_sockaddr_get_port(addr, &port));
        return port;
    }

    void fill_ep_params(uct_ep_params_t &params, uct_tcp_device_addr_t *dev_addr,
                        uct_tcp_iface_addr_t *iface_addr, uint16_t port,
                        entity *ent)
    {
        ASSERT_UCS_OK(uct_iface_get_device_address(ent->iface(),
                                                   (uct_device_addr_t*)dev_addr));
        iface_addr->port = htons(port);

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = ent->iface();
        params.dev_addr   = (uct_device_addr_t*)dev_addr;
        params.iface_addr = (uct_iface_addr_t*)iface_addr;
    }

    /* CONNECT_TO_IFACE EP on the iface of @a ent (default: the test's iface)
     * to a peer listening on @a port on the iface IP */
    uct_ep_h create_ep_to_port(uint16_t port, entity *ent = NULL)
    {
        if (ent == NULL) {
            ent = m_ent;
        }

        std::vector<uint8_t> dev_addr(ent->iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;
        uct_ep_h ep;

        fill_ep_params(params, (uct_tcp_device_addr_t*)&dev_addr[0],
                       &iface_addr, port, ent);
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    /* Listening raw socket whose address is lower than the iface address, so
     * that a CONNECT_TO_EP EP connected to it is the accepting side */
    bool raw_listener_lower(struct sockaddr_storage *listen_addr)
    {
        ucs_status_t status;
        int cmp;

        for (int i = 0; i < 64; ++i) {
            raw_listener(listen_addr);
            cmp = ucs_sockaddr_cmp((struct sockaddr*)listen_addr, iface_addr(),
                                   &status);
            ASSERT_UCS_OK(status);
            if (cmp < 0) {
                return true;
            }
        }

        return false;
    }

    /* CONNECT_TO_EP EP connected to a peer EP on @a listen_addr: the local
     * side is the accepting one, so the EP waits in ACCEPTING for CONN_REQ.
     * @a dev_addr and @a ep_addr are filled with the (fake) peer addresses
     * passed to uct_ep_connect_to_ep_v2() */
    uct_ep_h connect_to_ep_accepting(const struct sockaddr *listen_addr,
                                     std::vector<uint8_t> &dev_addr,
                                     std::vector<uint8_t> &ep_addr)
    {
        uct_tcp_ep_addr_t *remote_addr = (uct_tcp_ep_addr_t*)&ep_addr[0];
        uct_ep_connect_to_ep_params_t conn_params = {0};
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = m_ent->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        ASSERT_UCS_OK(uct_ep_get_address(ep, (uct_ep_addr_t*)&ep_addr[0]));
        ASSERT_UCS_OK(uct_iface_get_device_address(
                m_ent->iface(), (uct_device_addr_t*)&dev_addr[0]));
        remote_addr->iface_addr.port = htons(port_of(listen_addr));
        remote_addr->ptr_map_key     = 0x1234;

        ASSERT_UCS_OK(uct_ep_connect_to_ep_v2(ep,
                                              (uct_device_addr_t*)&dev_addr[0],
                                              (uct_ep_addr_t*)&ep_addr[0],
                                              &conn_params));
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
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

    bool err_reported(unsigned count)
    {
        return m_err_count >= count;
    }

    void wait_for_err(unsigned count = 1)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!err_reported(count) && (ucs_get_time() < deadline)) {
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

    /* Busy-wait for @a sec seconds without progressing anything */
    static void spin_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
        }
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

    void wait_for_ep_count(size_t count)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((ep_count() != count) && (ucs_get_time() < deadline)) {
            progress();
        }
    }

    /* uct_iface_close() while a user EP is still establishing a connection
     * and was not destroyed by the user: the EP is kept on the connection
     * matching context and is destroyed by the iface cleanup, which must
     * also take it off the timeout list - whether the deadline has expired
     * (but the EP was not swept yet) or not. The EP is destroyed, not
     * failed, so no error callback. A second iface is used so that all fds
     * of the iface (and of the EP) can be checked for leaks */
    void close_iface_with_armed_ep(bool expired)
    {
        struct sockaddr_storage listen_addr;
        uct_tcp_iface_t *tcp_iface;
        size_t fd_count;
        entity *ent;

        raw_listener(&listen_addr);
        fd_count      = open_fd_count();
        ent           = uct_test::create_entity(0, err_handler);
        tcp_iface     = ucs_derived_of(ent->iface(), uct_tcp_iface_t);
        uint16_t port = port_of((struct sockaddr*)&listen_addr);
        uct_ep_h ep   = create_ep_to_port(port, ent);

        EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
        EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_MATCH_CTX);
        EXPECT_FALSE(ucs_list_is_empty(&tcp_iface->conn_timeout_list));
        EXPECT_EQ(1u, tcp_iface->outstanding);

        if (expired) {
            spin_for(2 * CONN_TIMEOUT_SEC);
            EXPECT_LT(tcp_ep(ep)->conn_deadline, ucs_get_time());
        }

        /* closes the iface, which destroys the leaked EP */
        delete ent;

        EXPECT_EQ(0u, m_err_count);
        EXPECT_EQ(fd_count, open_fd_count());
    }

    /* Checks the invariants which must hold once the EP has been failed:
     * error callback fired exactly once, the EP is CLOSED, it is no longer
     * tracked by the timeout machinery, outstanding dropped to zero so the
     * iface can be flushed, and extra progress doesn't fire the callback
     * again */
    void check_failed_ep(uct_ep_h ep)
    {
        ASSERT_EQ(1u, m_err_count);
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
        EXPECT_EQ(ep, m_err_eps[0]);
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
        EXPECT_TRUE(ucs_list_is_empty(&m_tcp_iface->conn_timeout_list));
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

        progress_for(2 * CONN_TIMEOUT_SEC);
        EXPECT_EQ(1u, m_err_count);
    }

    uct_tcp_iface_t       *m_tcp_iface;
    entity                *m_ent;
    unsigned              m_err_count;
    ucs_status_t          m_err_status;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<int>      m_raw_fds;
    int                   m_err_cb_fd;
    std::vector<uint8_t>  m_err_cb_data;
};

const double test_uct_tcp_conn_timeout::CONN_TIMEOUT_SEC     = 0.2;
const double test_uct_tcp_conn_timeout::WAIT_TIMEOUT_SEC     = 10.0;
const size_t test_uct_tcp_conn_timeout::CONN_ACK_PKT_PREREAD = 2;

#define UCT_TCP_CONN_TIMEOUT_CFG "TCP_CONN_TIMEOUT=200ms"


/* Default: no timeout, an EP stuck in WAITING_ACK stays there and keeps the
 * iface outstanding (previous behaviour) */
UCS_TEST_P(test_uct_tcp_conn_timeout, default_is_inf)
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;

    EXPECT_EQ(UCS_TIME_INFINITY, m_tcp_iface->config.conn_timeout);

    raw_listener(&listen_addr);
    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));

    progress_for(5 * CONN_TIMEOUT_SEC);

    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
    EXPECT_TRUE(ucs_list_is_empty(&m_tcp_iface->conn_timeout_list));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    uct_ep_destroy(ep);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    EXPECT_EQ(fd_count, open_fd_count());
}

/* Peer accepts the TCP connection (kernel completes the 3-way handshake) but
 * never replies to CONN_REQ: EP is stuck in WAITING_ACK */
UCS_TEST_P(test_uct_tcp_conn_timeout, waiting_ack_stall,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;

    EXPECT_EQ(ucs_time_from_sec(CONN_TIMEOUT_SEC),
              m_tcp_iface->config.conn_timeout);

    raw_listener(&listen_addr);
    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));

    EXPECT_TRUE((conn_state(ep) == UCT_TCP_EP_CONN_STATE_CONNECTING) ||
                (conn_state(ep) == UCT_TCP_EP_CONN_STATE_WAITING_ACK));
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    wait_for_err();
    check_failed_ep(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* Non-blocking connect() which never completes: the listener's accept queue
 * is full so SYNs are dropped and the EP is stuck in CONNECTING */
UCS_TEST_P(test_uct_tcp_conn_timeout, connecting_stall,
           UCT_TCP_CONN_TIMEOUT_CFG, "TCP_CONN_NB=y")
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;

    raw_listener(&listen_addr, 0);
    /* Linux accepts backlog + 1 connections, over-fill the queue */
    for (int i = 0; i < 4; ++i) {
        raw_connect((struct sockaddr*)&listen_addr);
    }
    fd_count    = open_fd_count();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));

    if (conn_state(ep) != UCT_TCP_EP_CONN_STATE_CONNECTING) {
        uct_ep_destroy(ep);
        UCS_TEST_SKIP_R("connect() completed, accept queue not full");
    }

    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    wait_for_err();
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    check_failed_ep(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* Peer connects to the iface and sends the magic number but never sends
 * CONN_REQ: the internal RX EP created by the listener is stuck in ACCEPTING.
 * There is no user EP, so no error callback; the EP has to be destroyed and
 * the peer's socket closed */
UCS_TEST_P(test_uct_tcp_conn_timeout, accepting_stall,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    uint64_t magic = UCT_TCP_MAGIC_NUMBER;
    size_t fd_count;
    uint8_t byte;
    size_t len;
    ucs_status_t status;

    fd_count = open_fd_count();
    int fd   = raw_connect(iface_addr());

    /* wait for the connection to be established and send only the magic */
    while (!ucs_socket_is_connected(fd)) {
        progress();
    }
    ASSERT_UCS_OK(ucs_socket_send(fd, &magic, sizeof(magic)));

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(WAIT_TIMEOUT_SEC);
    while ((ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING) == 0) &&
           (ucs_get_time() < deadline)) {
        progress();
    }
    ASSERT_EQ(1u, ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_FALSE(ucs_list_is_empty(&m_tcp_iface->conn_timeout_list));
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    wait_for_ep_count(0);
    EXPECT_EQ(0u, ep_count());
    EXPECT_EQ(0u, m_err_count);
    EXPECT_TRUE(ucs_list_is_empty(&m_tcp_iface->conn_timeout_list));
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    /* the accepted socket must have been closed by the iface */
    deadline = ucs_get_time() + ucs_time_from_sec(WAIT_TIMEOUT_SEC);
    do {
        scoped_log_handler slh(wrap_errors_logger);
        len    = sizeof(byte);
        status = ucs_socket_recv_nb(fd, &byte, 0, &len);
    } while ((status == UCS_ERR_NO_PROGRESS) && (ucs_get_time() < deadline));
    EXPECT_NE(UCS_OK, status);
    EXPECT_NE(UCS_ERR_NO_PROGRESS, status);

    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* CONNECT_TO_EP: the local side is the one which has to accept (its address
 * is greater than the peer's), the peer never sends CONN_REQ: the user EP is
 * stuck in ACCEPTING and must be reported to the user */
UCS_TEST_P(test_uct_tcp_conn_timeout, connect_to_ep_accepting_stall,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
    std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
    struct sockaddr_storage listen_addr;
    size_t fd_count;
    uct_ep_h ep;

    if (!raw_listener_lower(&listen_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    fd_count = open_fd_count();
    ep       = connect_to_ep_accepting((struct sockaddr*)&listen_addr,
                                       dev_addr, ep_addr);
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    wait_for_err();
    check_failed_ep(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* uct_ep_connect_to_ep_v2() on a CONNECT_TO_EP EP which timed out while
 * waiting for CONN_REQ: the EP is CLOSED and not on the EP PTR map anymore
 * (like after a peer disconnect), so the call must report
 * UCS_ERR_CONNECTION_RESET without any further state change */
UCS_TEST_P(test_uct_tcp_conn_timeout, connect_to_ep_after_accepting_timeout,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
    std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
    uct_ep_connect_to_ep_params_t conn_params = {0};
    struct sockaddr_storage listen_addr;
    size_t fd_count;
    uct_ep_h ep;

    if (!raw_listener_lower(&listen_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    fd_count = open_fd_count();
    ep       = connect_to_ep_accepting((struct sockaddr*)&listen_addr,
                                       dev_addr, ep_addr);

    wait_for_err();
    check_failed_ep(ep);

    EXPECT_EQ(UCS_ERR_CONNECTION_RESET,
              uct_ep_connect_to_ep_v2(ep, (uct_device_addr_t*)&dev_addr[0],
                                      (uct_ep_addr_t*)&ep_addr[0],
                                      &conn_params));
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_TRUE(ucs_list_is_empty(&m_tcp_iface->conn_timeout_list));

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* Several EPs stalled at the same time: each is reported exactly once */
UCS_TEST_P(test_uct_tcp_conn_timeout, multiple_eps_stall,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    const unsigned num_eps = 8;
    struct sockaddr_storage listen_addr;
    std::vector<uct_ep_h> eps;

    raw_listener(&listen_addr);
    for (unsigned i = 0; i < num_eps; ++i) {
        eps.push_back(create_ep_to_port(port_of((struct sockaddr*)&listen_addr)));
    }
    EXPECT_EQ((size_t)num_eps, m_tcp_iface->outstanding);

    wait_for_err(num_eps);
    ASSERT_EQ(num_eps, m_err_count);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_TRUE(ucs_list_is_empty(&m_tcp_iface->conn_timeout_list));
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    std::sort(m_err_eps.begin(), m_err_eps.end());
    EXPECT_TRUE(std::unique(m_err_eps.begin(), m_err_eps.end()) ==
                m_err_eps.end());

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(num_eps, m_err_count);

    for (unsigned i = 0; i < num_eps; ++i) {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(eps[i]));
        uct_ep_destroy(eps[i]);
    }
}

/* The peer connected first and its CONN_REQ + partial CONN_ACK were read
 * into an internal EP, so uct_ep_create() takes over the socket through
 * uct_tcp_ep_replace_ep(), which schedules a one-shot RX progress for the
 * pre-read data. The timeout expires before the one-shot runs: the sweep
 * fails the EP (CLOSED, error callback) in the same uct_worker_progress()
 * in which the one-shot runs, and the rest of the CONN_ACK is written by
 * the error callback, i.e. after the event set was polled and before the
 * one-shot runs. The failed EP must stay CLOSED and must not process the
 * CONN_ACK (CLOSED->CONNECTED is illegal) */
UCS_TEST_P(test_uct_tcp_conn_timeout, replace_ep_preread_then_timeout,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    struct sockaddr_storage peer_addr;
    std::vector<uint8_t> ack_rest;
    size_t fd_count;

    raw_listener(&peer_addr);
    int fd   = preread_peer((struct sockaddr*)&peer_addr, ack_rest);
    fd_count = open_fd_count();

    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&peer_addr));
    /* the internal EP was taken over: no new socket, WAITING_ACK right away */
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(fd_count, open_fd_count());
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CONN_TIMEOUT_ARMED);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    m_err_cb_fd   = fd;
    m_err_cb_data = ack_rest;

    /* let the deadline expire without progressing, then a single progress:
     * event set (nothing readable) -> timeout sweep -> error callback writes
     * the rest of CONN_ACK -> one-shot RX progress of the pre-read data */
    spin_for(2 * CONN_TIMEOUT_SEC);
    progress();

    ASSERT_EQ(1u, m_err_count);
    EXPECT_TRUE(m_err_cb_data.empty());
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    /* the peer got our CONN_REQ before the EP failed */
    std::vector<uint8_t> req = raw_recv(fd, sizeof(uct_tcp_am_hdr_t) +
                                            sizeof(uct_tcp_cm_conn_req_pkt_t) +
                                            m_tcp_iface->config.sockaddr_len);
    EXPECT_EQ(UCT_TCP_EP_CM_AM_ID, req[0]);
    check_failed_ep(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count - 1, open_fd_count());
}

/* uct_iface_close() with a user EP which is still armed (CONNECTING /
 * WAITING_ACK): the iface cleanup must not assume the timeout list is empty
 * before the connection matching context, which holds the EP, is purged */
UCS_TEST_P(test_uct_tcp_conn_timeout, iface_close_armed_ep,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    close_iface_with_armed_ep(false);
}

/* Same with an EP whose deadline expired but which was not swept yet (no
 * progress between the deadline and uct_iface_close()) */
UCS_TEST_P(test_uct_tcp_conn_timeout, iface_close_expired_ep,
           UCT_TCP_CONN_TIMEOUT_CFG)
{
    close_iface_with_armed_ep(true);
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_conn_timeout, tcp)
