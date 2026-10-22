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
#include <algorithm>


/**
 * Exploratory tests for the asserted-illegal transitions of the TCP EP
 * connection state machine (uct_tcp_cm_change_conn_state()), with the focus
 * on an EP which was failed by UCX_TCP_CONN_TIMEOUT: once such an EP is
 * CLOSED, nothing (late CONN_ACK, late CONN_REQ, a pending one-shot RX
 * progress, a repeated uct_ep_connect_to_ep_v2) may move it anywhere but
 * CLOSED->CLOSED.
 *
 * Notes on the state machine which are documented rather than asserted:
 *  - X->CONNECTING for X not in {CLOSED, CONNECTING} is NOT asserted in
 *    uct_tcp_cm_change_conn_state(): the CONNECTING/WAITING_ACK case only
 *    checks (new == CONNECTING) || (old == CONNECTING). It is unreachable
 *    because uct_tcp_cm_conn_start() is called with conn_state CONNECTING
 *    (first attempt) or CLOSED (retry) only, and uct_tcp_ep_connect_to_ep_v2
 *    returns early for a CONNECTED EP (see connected_c2e_connect_again_noop).
 *
 * The peers in these tests are raw sockets fully controlled by the test, so
 * every packet on the wire is produced at a known point of the test. The only
 * timing dependency is the wait for the connection timeout itself.
 *
 * The tests only use fields which exist on master too (no PR-only symbols),
 * so the file compiles with and without the timeout feature; the
 * timeout-specific fixture skips when UCX_TCP_CONN_TIMEOUT does not exist.
 */
class test_uct_tcp_explore_illegal : public uct_test {
public:
    test_uct_tcp_explore_illegal() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_err_cb_fd(-1)
    {
    }

    void init()
    {
        uct_test::init();
        init_conn_timeout();
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
    static const double WAIT_TIMEOUT_SEC;
    static const double CONN_TIMEOUT_SEC;
    static const size_t CONN_ACK_PKT_PREREAD;

    virtual void init_conn_timeout()
    {
    }

    bool has_conn_timeout_cfg()
    {
        char value[64];
        return uct_config_get(m_iface_config, "CONN_TIMEOUT", value,
                              sizeof(value)) == UCS_OK;
    }

    /* The error callback optionally writes raw bytes into a peer socket.
     * This is how a test places data on the wire at a point which is inside
     * uct_tcp_iface_progress(): after epoll was already polled and the
     * timeout sweep failed the EP, but before the one-shot callbacks of the
     * worker progress queue run. */
    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_illegal *self =
                reinterpret_cast<test_uct_tcp_explore_illegal*>(arg);

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
        DIR *dir     = opendir("/proc/self/fd");
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
     * connection by itself and never speaks the UCT TCP protocol */
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

    /* Listening socket whose address compares lower than the iface address,
     * so that the local iface is the accepting side of a CONNECT_TO_EP
     * connection to it */
    int raw_listener_lower(struct sockaddr_storage *addr)
    {
        ucs_status_t status;
        int cmp = 1;
        int fd  = -1;

        for (int i = 0; (i < 64) && (cmp >= 0); ++i) {
            fd  = raw_listener(addr);
            cmp = ucs_sockaddr_cmp((struct sockaddr*)addr, iface_addr(),
                                   &status);
            ASSERT_UCS_OK(status);
        }
        if (cmp >= 0) {
            UCS_TEST_SKIP_R("could not get a peer port lower than the iface "
                            "port");
        }
        return fd;
    }

    /* Non-blocking raw socket connected to @a addr (progresses the iface
     * until the connection is established) */
    int raw_connect(const struct sockaddr *addr)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        int fd;

        ASSERT_UCS_OK(ucs_socket_create(addr->sa_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);
        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));

        ucs_status_t status = ucs_socket_connect(fd, addr);
        EXPECT_TRUE((status == UCS_OK) || (status == UCS_INPROGRESS));

        while (!ucs_socket_is_connected(fd) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_TRUE(ucs_socket_is_connected(fd));
        return fd;
    }

    /* Accept the connection which the kernel completed on the raw listener */
    int raw_accept(int listen_fd)
    {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int fd;

        ASSERT_UCS_OK(ucs_socket_accept(listen_fd, (struct sockaddr*)&addr,
                                        &addr_len, &fd));
        m_raw_fds.push_back(fd);
        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));
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

    /* true when the remote side closed the raw socket */
    bool raw_peer_closed(int fd)
    {
        uint8_t buf[64];
        size_t length = sizeof(buf);
        ucs_status_t status;

        do {
            length = sizeof(buf);
            status = ucs_socket_recv_nb(fd, buf, 0, &length);
        } while (status == UCS_OK);
        return status != UCS_ERR_NO_PROGRESS;
    }

    void wait_for_peer_closed(int fd)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!raw_peer_closed(fd) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_TRUE(raw_peer_closed(fd));
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

    /* Close a raw socket owned by the test */
    void raw_close(int fd)
    {
        m_raw_fds.erase(std::find(m_raw_fds.begin(), m_raw_fds.end(), fd));
        close(fd);
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

    /* CONN_REQ as sent by a connecting peer: [magic] + AM hdr + req + addr */
    std::vector<uint8_t> conn_req_pkt(const struct sockaddr *peer_addr,
                                      uct_tcp_ep_cm_id_t cm_id, uint8_t flags,
                                      bool with_magic)
    {
        std::vector<uint8_t> pkt;
        uct_tcp_cm_conn_req_pkt_t req;
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;

        if (with_magic) {
            append(pkt, &magic, sizeof(magic));
        }
        append_am_hdr(pkt, sizeof(req) + m_tcp_iface->config.sockaddr_len);
        req.event = UCT_TCP_CM_CONN_REQ;
        req.flags = flags;
        req.cm_id = cm_id;
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

    /* Size of the CONN_REQ a WAITING_ACK EP sends (no magic number) */
    size_t conn_req_size() const
    {
        return sizeof(uct_tcp_am_hdr_t) + sizeof(uct_tcp_cm_conn_req_pkt_t) +
               m_tcp_iface->config.sockaddr_len;
    }

    void raw_send(int fd, const std::vector<uint8_t> &data)
    {
        ASSERT_UCS_OK(ucs_socket_send(fd, &data[0], data.size()));
    }

    /* CONNECT_TO_IFACE EP to @a addr */
    uct_ep_h create_ep_to_addr(const struct sockaddr *addr)
    {
        std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
        uct_tcp_iface_addr_t iface_addr;
        uct_ep_params_t params;
        uint16_t port = 0;
        uct_ep_h ep;

        ASSERT_UCS_OK(uct_iface_get_device_address(m_ent->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        ASSERT_UCS_OK(ucs_sockaddr_get_port(addr, &port));
        iface_addr.port = htons(port);

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE |
                            UCT_EP_PARAM_FIELD_DEV_ADDR |
                            UCT_EP_PARAM_FIELD_IFACE_ADDR;
        params.iface      = m_ent->iface();
        params.dev_addr   = (uct_device_addr_t*)&dev_addr[0];
        params.iface_addr = (uct_iface_addr_t*)&iface_addr;
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    /* CONNECT_TO_EP EP, not connected yet */
    uct_ep_h create_c2e_ep()
    {
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = m_ent->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    /* uct_ep_connect_to_ep_v2(ep) towards a peer with the EP address of
     * @a ep itself but the port of @a peer_addr and @a ptr_map_key */
    ucs_status_t connect_c2e_ep(uct_ep_h ep, const struct sockaddr *peer_addr,
                                ucs_ptr_map_key_t ptr_map_key)
    {
        std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
        std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
        uct_tcp_ep_addr_t *remote_addr = (uct_tcp_ep_addr_t*)&ep_addr[0];
        uct_ep_connect_to_ep_params_t conn_params = {0};
        uint16_t port = 0;

        ASSERT_UCS_OK(uct_ep_get_address(ep, (uct_ep_addr_t*)&ep_addr[0]));
        ASSERT_UCS_OK(uct_iface_get_device_address(m_ent->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        ASSERT_UCS_OK(ucs_sockaddr_get_port(peer_addr, &port));
        remote_addr->iface_addr.port = htons(port);
        remote_addr->ptr_map_key     = ptr_map_key;

        return uct_ep_connect_to_ep_v2(ep, (uct_device_addr_t*)&dev_addr[0],
                                       (uct_ep_addr_t*)&ep_addr[0],
                                       &conn_params);
    }

    /* uct_ep_connect_to_ep_v2(from) with the real addresses of @a to */
    static ucs_status_t connect_ep_to_ep(uct_ep_h from, uct_ep_h to)
    {
        uct_ep_connect_to_ep_params_t params = {0};
        uct_iface_attr_t iface_attr;

        ASSERT_UCS_OK(uct_iface_query(to->iface, &iface_attr));
        std::vector<uint8_t> dev_addr(iface_attr.device_addr_len);
        std::vector<uint8_t> ep_addr(iface_attr.ep_addr_len);

        ASSERT_UCS_OK(uct_iface_get_device_address(to->iface,
                                                   (uct_device_addr_t*)&dev_addr[0]));
        ASSERT_UCS_OK(uct_ep_get_address(to, (uct_ep_addr_t*)&ep_addr[0]));
        return uct_ep_connect_to_ep_v2(from, (uct_device_addr_t*)&dev_addr[0],
                                       (uct_ep_addr_t*)&ep_addr[0], &params);
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

    void wait_for_state(uct_ep_h ep, uct_tcp_ep_conn_state_t state)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((conn_state(ep) != state) && (ucs_get_time() < deadline)) {
            progress();
        }
        EXPECT_EQ(state, conn_state(ep));
    }

    /* Progress for @a sec seconds, wall clock */
    void progress_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
            progress();
        }
    }

    /* Busy-wait without progressing anything */
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

    /* Invariants of an EP which was failed by the timeout */
    void check_failed_ep(uct_ep_h ep)
    {
        ASSERT_EQ(1u, m_err_count);
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
        EXPECT_EQ(ep, m_err_eps[0]);
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    }

    /* Invariants which must still hold after an attempt to push a failed
     * EP back into the state machine: nothing but CLOSED->CLOSED happened */
    void check_still_failed(uct_ep_h ep)
    {
        progress_for(0.05);
        EXPECT_EQ(1u, m_err_count);
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    }

    /* Peer which connects to the iface and sends magic + CONN_REQ(conn_sn 0,
     * address @a peer_addr) followed by the first CONN_ACK_PKT_PREREAD bytes
     * of a CONN_ACK packet. The iface creates an internal RX-only EP, which
     * becomes CONNECTED, is kept on the connection matching context as
     * unexpected and keeps the partial CONN_ACK in its RX buffer. Returns
     * the peer socket; the remaining CONN_ACK bytes are returned in
     * @a ack_rest. */
    int preread_peer(const struct sockaddr *peer_addr,
                     std::vector<uint8_t> &ack_rest)
    {
        std::vector<uint8_t> ack = conn_ack_pkt();
        std::vector<uint8_t> pkt;
        uct_tcp_ep_cm_id_t cm_id;
        int fd;

        EXPECT_TRUE(CONN_ACK_PKT_PREREAD < sizeof(uct_tcp_am_hdr_t));

        fd            = raw_connect(iface_addr());
        cm_id.conn_sn = 0;
        pkt           = conn_req_pkt(peer_addr, cm_id, 0, true);
        append(pkt, &ack[0], CONN_ACK_PKT_PREREAD);
        raw_send(fd, pkt);

        /* the internal EP replies with CONN_ACK once it is CONNECTED */
        std::vector<uint8_t> reply = raw_recv(fd, ack.size());
        EXPECT_EQ(ack, reply);

        ack_rest.assign(ack.begin() + CONN_ACK_PKT_PREREAD, ack.end());
        return fd;
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

const double test_uct_tcp_explore_illegal::WAIT_TIMEOUT_SEC      = 10.0;
const double test_uct_tcp_explore_illegal::CONN_TIMEOUT_SEC      = 0.3;
const size_t test_uct_tcp_explore_illegal::CONN_ACK_PKT_PREREAD  = 2;


/* uct_tcp_ep_replace_ep() pre-read path without any timeout (baseline, runs
 * on master as well): the one-shot uct_tcp_ep_progress_data_rx scheduled by
 * uct_tcp_ep_replace_ep() reads the rest of the CONN_ACK and completes
 * WAITING_ACK->CONNECTED legally */
UCS_TEST_P(test_uct_tcp_explore_illegal, replace_ep_preread_conn_ack_connects)
{
    struct sockaddr_storage peer_addr;
    std::vector<uint8_t> ack_rest;
    size_t fd_count;

    raw_listener(&peer_addr);
    int fd   = preread_peer((struct sockaddr*)&peer_addr, ack_rest);
    fd_count = open_fd_count();

    uct_ep_h ep = create_ep_to_addr((struct sockaddr*)&peer_addr);
    /* the internal EP was taken over: no new socket, WAITING_ACK right away */
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(fd_count, open_fd_count());
    EXPECT_EQ(1u, tcp_ep(ep)->conn_retries);
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    /* complete the pre-read CONN_ACK before the first progress */
    raw_send(fd, ack_rest);
    wait_for_state(ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    /* the peer got our CONN_REQ (no magic number from WAITING_ACK) */
    std::vector<uint8_t> req = raw_recv(fd, conn_req_size());
    EXPECT_EQ(UCT_TCP_EP_CM_AM_ID, req[0]);

    /* a CONNECTED full-duplex EP turns into an RX-only internal EP on
     * destroy and sends CONN_FIN; it is destroyed once the peer closes */
    uct_ep_destroy(ep);
    std::vector<uint8_t> fin = raw_recv(fd, conn_ack_pkt().size());
    EXPECT_EQ(UCT_TCP_EP_CM_AM_ID, fin[0]);
    raw_close(fd);
    wait_for_fd_count(fd_count - 2);
}

/* X->CONNECTING is not asserted; the only API path which could re-enter it
 * for a CONNECT_TO_EP EP is a second uct_ep_connect_to_ep_v2, which must
 * return UCS_OK early for a CONNECTED EP (and ACCEPTING cannot be re-entered
 * through a repeated CONN_REQ either) */
UCS_TEST_P(test_uct_tcp_explore_illegal, connected_c2e_connect_again_noop)
{
    entity *peer = uct_test::create_entity(0, err_handler);
    m_entities.push_back(peer);
    uct_tcp_iface_t *peer_iface = ucs_derived_of(peer->iface(),
                                                 uct_tcp_iface_t);

    m_ent->connect_to_ep(0, *peer, 0);
    uct_ep_h ep      = m_ent->ep(0);
    uct_ep_h peer_ep = peer->ep(0);

    wait_for_state(ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    wait_for_state(peer_ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    flush();
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_EQ(0u, peer_iface->outstanding);

    unsigned retries      = tcp_ep(ep)->conn_retries;
    unsigned peer_retries = tcp_ep(peer_ep)->conn_retries;

    /* repeat connect_to_ep on both sides (the uct_test helper does the same
     * address exchange) */
    for (int i = 0; i < 2; ++i) {
        EXPECT_UCS_OK(connect_ep_to_ep(ep, peer_ep));
        EXPECT_UCS_OK(connect_ep_to_ep(peer_ep, ep));
        progress_for(0.02);
    }

    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(peer_ep));
    EXPECT_EQ(retries, tcp_ep(ep)->conn_retries);
    EXPECT_EQ(peer_retries, tcp_ep(peer_ep)->conn_retries);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_EQ(0u, peer_iface->outstanding);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
    EXPECT_EQ(-1, tcp_ep(peer_ep)->stale_fd);
    flush();
}

/* Pre-existing behaviour, documented for the timeout tests below: a second
 * uct_ep_connect_to_ep_v2 on an EP which is still ACCEPTING trips the
 * X->ACCEPTING assertion in uct_tcp_cm_change_conn_state() (old state must
 * be RECV_MAGIC_NUMBER or CLOSED). Aborts the process in a debug build, so it
 * only runs on request. */
UCS_TEST_P(test_uct_tcp_explore_illegal, c2e_connect_twice_while_accepting)
{
    struct sockaddr_storage listen_addr;

    if (getenv("UCX_GTEST_EXPLORE_ASSERTS") == NULL) {
        UCS_TEST_SKIP_R("trips ucs_assert; set UCX_GTEST_EXPLORE_ASSERTS=y");
    }

    raw_listener_lower(&listen_addr);
    uct_ep_h ep = create_c2e_ep();
    ASSERT_UCS_OK(connect_c2e_ep(ep, (struct sockaddr*)&listen_addr, 0x1234));
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));

    ucs_status_t status = connect_c2e_ep(ep, (struct sockaddr*)&listen_addr,
                                         0x1234);
    UCS_TEST_MESSAGE << "second connect_to_ep: " << ucs_status_string(status);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    uct_ep_destroy(ep);
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_illegal, tcp)


/**
 * Timeout-specific tests: UCX_TCP_CONN_TIMEOUT is set to CONN_TIMEOUT_SEC,
 * skipped when the config does not exist (master).
 */
class test_uct_tcp_explore_illegal_timeout : public test_uct_tcp_explore_illegal {
protected:
    virtual void init_conn_timeout()
    {
        if (!has_conn_timeout_cfg()) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT config does not exist");
        }
        modify_config("TCP_CONN_TIMEOUT",
                      ucs::to_string(unsigned(CONN_TIMEOUT_SEC * 1000)) + "ms",
                      IGNORE_IF_NOT_EXIST);
    }
};

/* (1) A CONN_ACK which arrives after the WAITING_ACK timeout: the EP must
 * stay CLOSED (events == 0, so the packet is never read), no second error
 * callback, no CLOSED->CONNECTED */
UCS_TEST_P(test_uct_tcp_explore_illegal_timeout, waiting_ack_timeout_late_conn_ack)
{
    struct sockaddr_storage listen_addr;
    size_t fd_count;

    int lfd  = raw_listener(&listen_addr);
    fd_count = open_fd_count();

    uct_ep_h ep = create_ep_to_addr((struct sockaddr*)&listen_addr);
    wait_for_err();
    check_failed_ep(ep);

    /* the peer now accepts, consumes the handshake and answers CONN_ACK */
    int pfd = raw_accept(lfd);
    std::vector<uint8_t> req = raw_recv(pfd, sizeof(uint64_t) +
                                             conn_req_size());
    EXPECT_EQ(UCT_TCP_MAGIC_NUMBER, *(uint64_t*)&req[0]);
    raw_send(pfd, conn_ack_pkt());

    check_still_failed(ep);

    uct_ep_destroy(ep);
    wait_for_peer_closed(pfd);
    EXPECT_EQ(fd_count + 1, open_fd_count()); /* +1: the accepted peer fd */
}

/* (2) uct_tcp_ep_replace_ep() pre-read path crossed with the timeout: the
 * sweep fails the WAITING_ACK EP (CLOSED, error callback) in the same
 * uct_worker_progress in which the one-shot uct_tcp_ep_progress_data_rx
 * scheduled by uct_tcp_ep_replace_ep() runs. The rest of the CONN_ACK is
 * written by the error callback, i.e. after epoll was polled and before the
 * one-shot runs, so the one-shot finds a complete CONN_ACK on a CLOSED EP.
 * Expected: the EP stays CLOSED, events == 0, no CLOSED->CONNECTED.
 * Observed: uct_tcp_cm_handle_conn_ack() moves the CLOSED EP to CONNECTED and
 * trips the CLOSED->CONNECTED assertion in uct_tcp_cm_change_conn_state()
 * (tcp_cm.c), aborting a debug build; therefore it only runs on request. */
UCS_TEST_P(test_uct_tcp_explore_illegal_timeout, replace_ep_preread_then_timeout)
{
    struct sockaddr_storage peer_addr;
    std::vector<uint8_t> ack_rest;
    size_t fd_count;

    if (getenv("UCX_GTEST_EXPLORE_ASSERTS") == NULL) {
        UCS_TEST_SKIP_R("trips ucs_assert; set UCX_GTEST_EXPLORE_ASSERTS=y");
    }

    raw_listener(&peer_addr);
    int fd   = preread_peer((struct sockaddr*)&peer_addr, ack_rest);
    fd_count = open_fd_count();

    uct_ep_h ep = create_ep_to_addr((struct sockaddr*)&peer_addr);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    m_err_cb_fd   = fd;
    m_err_cb_data = ack_rest;

    /* let the deadline expire without progressing, then a single progress:
     * epoll (nothing readable) -> timeout sweep -> error callback writes the
     * CONN_ACK -> one-shot progress_data_rx on the CLOSED EP */
    spin_for(2 * CONN_TIMEOUT_SEC);
    progress();

    ASSERT_EQ(1u, m_err_count);
    EXPECT_TRUE(m_err_cb_data.empty()); /* the callback did write it */
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    check_still_failed(ep);

    /* the peer got our CONN_REQ before the EP failed */
    std::vector<uint8_t> req = raw_recv(fd, conn_req_size());
    EXPECT_EQ(UCT_TCP_EP_CM_AM_ID, req[0]);

    uct_ep_destroy(ep);
    wait_for_peer_closed(fd);
    EXPECT_EQ(fd_count - 1, open_fd_count());
}

/* A late CONN_REQ claiming the ptr-map key of a CONNECT_TO_EP EP which timed
 * out in ACCEPTING: uct_tcp_ep_ptr_map_retrieve() returns NULL, the internal
 * EP is dropped, the user EP stays CLOSED (no CLOSED->CONNECTED, no
 * CONNECTED->ACCEPTING), no second error callback */
UCS_TEST_P(test_uct_tcp_explore_illegal_timeout, c2e_accepting_timeout_late_conn_req)
{
    struct sockaddr_storage listen_addr;
    uct_tcp_ep_cm_id_t cm_id;
    size_t fd_count;

    raw_listener_lower(&listen_addr);
    fd_count    = open_fd_count();
    uct_ep_h ep = create_c2e_ep();
    ASSERT_UCS_OK(connect_c2e_ep(ep, (struct sockaddr*)&listen_addr, 0x1234));
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    wait_for_err();
    check_failed_ep(ep);
    size_t num_eps = ep_count();

    /* the peer finally connects and sends CONN_REQ for the failed EP */
    cm_id.ptr_map_key = tcp_ep(ep)->cm_id.ptr_map_key;
    int pfd = raw_connect(iface_addr());
    raw_send(pfd, conn_req_pkt((struct sockaddr*)&listen_addr, cm_id,
                               UCT_TCP_CM_CONN_REQ_PKT_FLAG_CONNECT_TO_EP,
                               true));

    /* the internal EP is destroyed -> the peer sees EOF */
    wait_for_peer_closed(pfd);
    EXPECT_EQ(num_eps, ep_count());
    check_still_failed(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(fd_count + 1, open_fd_count()); /* +1: the raw peer socket */
}

/* (3) uct_ep_connect_to_ep_v2 on a CONNECT_TO_EP EP which timed out in
 * ACCEPTING: the EP is CLOSED and off the ptr map, so the function reports
 * UCS_ERR_CONNECTION_RESET, but only after ucs_assert(ep->conn_retries > 0),
 * which the timeout path never incremented. Aborts the process in a debug
 * build, so it only runs on request (compare with
 * c2e_connect_twice_while_accepting, which asserts on master as well). */
UCS_TEST_P(test_uct_tcp_explore_illegal_timeout, c2e_connect_again_after_accepting_timeout)
{
    struct sockaddr_storage listen_addr;

    if (getenv("UCX_GTEST_EXPLORE_ASSERTS") == NULL) {
        UCS_TEST_SKIP_R("trips ucs_assert; set UCX_GTEST_EXPLORE_ASSERTS=y");
    }

    raw_listener_lower(&listen_addr);
    uct_ep_h ep = create_c2e_ep();
    ASSERT_UCS_OK(connect_c2e_ep(ep, (struct sockaddr*)&listen_addr, 0x1234));
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));

    wait_for_err();
    check_failed_ep(ep);
    EXPECT_EQ(0u, tcp_ep(ep)->conn_retries);

    ucs_status_t status = connect_c2e_ep(ep, (struct sockaddr*)&listen_addr,
                                         0x1234);
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET, status);
    check_still_failed(ep);

    uct_ep_destroy(ep);
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_illegal_timeout, tcp)
