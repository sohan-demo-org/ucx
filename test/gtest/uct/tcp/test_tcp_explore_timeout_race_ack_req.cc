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
 * Exploration of UCX_TCP_CONN_TIMEOUT racing with CONN_ACK / CONN_REQ.
 *
 * The race is made deterministic by controlling exactly when
 * uct_iface_progress() is called: the peer is a raw socket, the deadline is
 * passed WITHOUT progressing, and then the CM packet is written into the raw
 * socket either before or after a single progress call. Tests which need the
 * timeout skip when the config knob does not exist (base branch).
 */
class test_uct_tcp_explore_timeout_race : public uct_test {
public:
    test_uct_tcp_explore_timeout_race() :
        m_tcp_iface(NULL), m_ent(NULL), m_err_count(0), m_err_status(UCS_OK),
        m_has_conn_timeout(false)
    {
    }

    void init()
    {
        uct_test::init();
        modify_config("TCP_CONN_TIMEOUT", CONN_TIMEOUT_STR, IGNORE_IF_NOT_EXIST);
        m_ent = uct_test::create_entity(0, err_handler);
        m_entities.push_back(m_ent);
        m_tcp_iface        = ucs_derived_of(m_ent->iface(), uct_tcp_iface_t);
        m_has_conn_timeout = iface_has_conn_timeout();
    }

    void cleanup()
    {
        close_fds(m_raw_fds);
        uct_test::cleanup();
    }

protected:
    static const double CONN_TIMEOUT_SEC;
    static const double WAIT_TIMEOUT_SEC;
    static const char   *CONN_TIMEOUT_STR;
    static const uint8_t TEST_AM_ID = 7;

    static ucs_status_t err_handler(void *arg, uct_ep_h ep, ucs_status_t status)
    {
        test_uct_tcp_explore_timeout_race *self =
                reinterpret_cast<test_uct_tcp_explore_timeout_race*>(arg);

        self->m_err_count++;
        self->m_err_status = status;
        self->m_err_eps.push_back(ep);
        return UCS_OK;
    }

    static ucs_status_t am_handler(void *arg, void *data, size_t length,
                                   unsigned flags)
    {
        unsigned *count = reinterpret_cast<unsigned*>(arg);
        (*count)++;
        return UCS_OK;
    }

    /* Only PR-introduced symbols must not be used: detect the knob via the
     * generic config API so that this file compiles on the base branch */
    bool iface_has_conn_timeout()
    {
        uct_iface_config_t *cfg;
        char value[64];
        ucs_status_t status;

        status = uct_md_iface_config_read(m_ent->md(),
                                          GetParam()->tl_name.c_str(), NULL,
                                          NULL, &cfg);
        if (status != UCS_OK) {
            return false;
        }

        status = uct_config_get(cfg, "CONN_TIMEOUT", value, sizeof(value));
        uct_config_release(cfg);
        return status == UCS_OK;
    }

    void require_conn_timeout()
    {
        if (!m_has_conn_timeout) {
            UCS_TEST_SKIP_R("UCX_TCP_CONN_TIMEOUT is not supported");
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

    size_t sockaddr_len() const
    {
        return m_tcp_iface->config.sockaddr_len;
    }

    /* Listening socket on the iface IP address which never speaks the UCT
     * TCP protocol by itself */
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

        EXPECT_EQ(0, bind(fd, (struct sockaddr*)addr, addr_size));
        EXPECT_EQ(0, listen(fd, 16));
        ASSERT_UCS_OK(ucs_socket_getname(fd, addr, &addr_len));
        return fd;
    }

    /* Listener whose address compares lower than the iface address, so that
     * the local (iface) side is the accepting side of a CONNECT_TO_EP
     * connection. Returns false if no such port could be obtained. */
    bool raw_listener_lower(struct sockaddr_storage *addr)
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

    /* Blocking raw socket connected to @a addr */
    int raw_connect(const struct sockaddr *addr)
    {
        size_t addr_size;
        int fd;

        ASSERT_UCS_OK(ucs_sockaddr_sizeof(addr, &addr_size));
        ASSERT_UCS_OK(ucs_socket_create(addr->sa_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);
        EXPECT_EQ(0, connect(fd, addr, addr_size)) << strerror(errno);
        return fd;
    }

    /* Blocking accept() on @a listen_fd (the connection is already queued) */
    int raw_accept(int listen_fd)
    {
        int fd = accept(listen_fd, NULL, NULL);
        EXPECT_GE(fd, 0) << strerror(errno);
        m_raw_fds.push_back(fd);
        return fd;
    }

    void raw_recv_all(int fd, void *buf, size_t length)
    {
        size_t offset = 0;

        while (offset < length) {
            ssize_t ret = recv(fd, UCS_PTR_BYTE_OFFSET(buf, offset),
                               length - offset, 0);
            ASSERT_GT(ret, 0) << strerror(errno);
            offset += ret;
        }
    }

    void raw_send_all(int fd, const void *buf, size_t length)
    {
        ASSERT_UCS_OK(ucs_socket_send(fd, buf, length));
    }

    /* Returns true if the peer closed the connection (recv returns 0 or an
     * error), polling with progress until @a WAIT_TIMEOUT_SEC */
    bool raw_wait_peer_closed(int fd)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        uint8_t byte;

        ASSERT_UCS_OK(ucs_sys_fcntl_modfl(fd, O_NONBLOCK, 0));
        while (ucs_get_time() < deadline) {
            ssize_t ret = recv(fd, &byte, sizeof(byte), 0);
            if (ret == 0) {
                return true;
            } else if ((ret < 0) && (errno != EAGAIN) &&
                       (errno != EWOULDBLOCK)) {
                return true;
            }
            progress();
        }
        return false;
    }

    /* Reads the client side of the handshake (magic + CONN_REQ) which the
     * UCT EP sends right after connect() */
    void raw_recv_conn_req(int fd, uct_tcp_cm_conn_req_pkt_t *req)
    {
        uint64_t magic;
        uct_tcp_am_hdr_t hdr;
        std::vector<uint8_t> payload;

        raw_recv_all(fd, &magic, sizeof(magic));
        ASSERT_EQ((uint64_t)UCT_TCP_MAGIC_NUMBER, magic);
        raw_recv_all(fd, &hdr, sizeof(hdr));
        ASSERT_EQ((uint8_t)UCT_TCP_EP_CM_AM_ID, hdr.am_id);
        ASSERT_EQ(sizeof(*req) + sockaddr_len(), hdr.length);
        payload.resize(hdr.length);
        raw_recv_all(fd, &payload[0], payload.size());
        memcpy(req, &payload[0], sizeof(*req));
        ASSERT_EQ(UCT_TCP_CM_CONN_REQ, req->event);
    }

    void raw_send_conn_ack(int fd)
    {
        uct_tcp_am_hdr_t hdr;
        uct_tcp_cm_conn_event_t event = UCT_TCP_CM_CONN_ACK;

        hdr.am_id  = UCT_TCP_EP_CM_AM_ID;
        hdr.length = sizeof(event);
        raw_send_all(fd, &hdr, sizeof(hdr));
        raw_send_all(fd, &event, sizeof(event));
    }

    /* Peer side of a CONNECT_TO_EP connection: magic number followed by
     * CONN_REQ carrying the CONNECT_TO_EP flag, the local EP's ptr map key
     * and the peer's (lower) address */
    void raw_send_c2e_conn_req(int fd, ucs_ptr_map_key_t ptr_map_key,
                               const struct sockaddr *peer_addr)
    {
        uint64_t magic = UCT_TCP_MAGIC_NUMBER;
        uct_tcp_am_hdr_t hdr;
        uct_tcp_cm_conn_req_pkt_t req;

        memset(&req, 0, sizeof(req));
        req.event             = UCT_TCP_CM_CONN_REQ;
        req.flags             = UCT_TCP_CM_CONN_REQ_PKT_FLAG_CONNECT_TO_EP;
        req.cm_id.ptr_map_key = ptr_map_key;

        hdr.am_id  = UCT_TCP_EP_CM_AM_ID;
        hdr.length = sizeof(req) + sockaddr_len();

        raw_send_all(fd, &magic, sizeof(magic));
        raw_send_all(fd, &hdr, sizeof(hdr));
        raw_send_all(fd, &req, sizeof(req));
        raw_send_all(fd, peer_addr, sockaddr_len());
    }

    /* Reads one AM (header + payload) sent by the UCT EP */
    void raw_recv_am(int fd, uint8_t exp_am_id, uint64_t exp_header)
    {
        uct_tcp_am_hdr_t hdr;
        uint64_t header;

        raw_recv_all(fd, &hdr, sizeof(hdr));
        ASSERT_EQ(exp_am_id, hdr.am_id);
        ASSERT_EQ(sizeof(header), hdr.length);
        raw_recv_all(fd, &header, sizeof(header));
        EXPECT_EQ(exp_header, header);
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

        ASSERT_UCS_OK(uct_iface_get_device_address(m_ent->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
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

    /* CONNECT_TO_EP EP (no peer yet) */
    uct_ep_h create_c2e_ep()
    {
        uct_ep_params_t params;
        uct_ep_h ep;

        params.field_mask = UCT_EP_PARAM_FIELD_IFACE;
        params.iface      = m_ent->iface();
        ASSERT_UCS_OK(uct_ep_create(&params, &ep));
        return ep;
    }

    /* Connects a CONNECT_TO_EP EP to a peer at @a peer_addr (which must be
     * lower than the iface address so that the local side accepts) */
    void c2e_connect_accept_side(uct_ep_h ep, const struct sockaddr *peer_addr)
    {
        std::vector<uint8_t> dev_addr(m_ent->iface_attr().device_addr_len);
        std::vector<uint8_t> ep_addr(m_ent->iface_attr().ep_addr_len);
        uct_tcp_ep_addr_t *remote_addr = (uct_tcp_ep_addr_t*)&ep_addr[0];
        uct_ep_connect_to_ep_params_t conn_params = {0};

        ASSERT_UCS_OK(uct_ep_get_address(ep, (uct_ep_addr_t*)&ep_addr[0]));
        ASSERT_UCS_OK(uct_iface_get_device_address(m_ent->iface(),
                                                   (uct_device_addr_t*)&dev_addr[0]));
        remote_addr->iface_addr.port = htons(port_of(peer_addr));
        remote_addr->ptr_map_key     = 0x1234;
        ASSERT_UCS_OK(uct_ep_connect_to_ep_v2(ep, (uct_device_addr_t*)&dev_addr[0],
                                              (uct_ep_addr_t*)&ep_addr[0],
                                              &conn_params));
    }

    static uct_tcp_ep_t *tcp_ep(uct_ep_h ep)
    {
        return ucs_derived_of(ep, uct_tcp_ep_t);
    }

    static uct_tcp_ep_conn_state_t conn_state(uct_ep_h ep)
    {
        return (uct_tcp_ep_conn_state_t)tcp_ep(ep)->conn_state;
    }

    static ucs_ptr_map_key_t ptr_map_key(uct_ep_h ep)
    {
        return tcp_ep(ep)->cm_id.ptr_map_key;
    }

    /* Let the connection deadline pass WITHOUT calling progress: the EP was
     * armed no later than @a armed_at, so after this returns any sweep must
     * consider it expired */
    void pass_deadline_without_progress(ucs_time_t armed_at)
    {
        ucs_time_t deadline = armed_at +
                              ucs_time_from_sec(1.5 * CONN_TIMEOUT_SEC);
        while (ucs_get_time() < deadline) {
            /* busy wait, intentionally no progress */
        }
    }

    unsigned progress_once()
    {
        return uct_iface_progress(m_ent->iface());
    }

    /* Progress for @a sec seconds, wall clock */
    void progress_for(double sec)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(sec);
        while (ucs_get_time() < deadline) {
            progress();
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

    void wait_for_conn_state(uct_ep_h ep, uct_tcp_ep_conn_state_t state)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while ((conn_state(ep) != state) && (ucs_get_time() < deadline)) {
            progress();
        }
    }

    /* Invariants of a connected user EP */
    void check_connected_ep(uct_ep_h ep)
    {
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CONNECTED, conn_state(ep));
        EXPECT_EQ(0u, m_err_count);
        EXPECT_NE(-1, tcp_ep(ep)->fd);
        EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);
        EXPECT_TRUE(tcp_ep(ep)->events & UCS_EVENT_SET_EVREAD);
        EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CTX_TYPE_TX);
        EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_FAILED);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    }

    /* Invariants of a user EP failed by the timeout */
    void check_failed_ep(uct_ep_h ep)
    {
        ASSERT_EQ(1u, m_err_count);
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status);
        EXPECT_EQ(ep, m_err_eps[0]);
        EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
        EXPECT_EQ(0u, tcp_ep(ep)->events);
        EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
        EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));
    }

    /* An AM short on @a ep must be delivered to the raw peer @a fd */
    void check_send_works(uct_ep_h ep, int fd)
    {
        const uint64_t header = 0xdeadbeefcafe1234ul;

        /* uct_ep_flush() is not used here: after an AM it posts a PUT flush
         * request which needs a PUT ACK from a real UCT peer */
        ASSERT_UCS_OK(uct_ep_am_short(ep, TEST_AM_ID, header, NULL, 0));
        raw_recv_am(fd, TEST_AM_ID, header);
        EXPECT_EQ(0u, m_tcp_iface->outstanding);
    }

    uct_tcp_iface_t       *m_tcp_iface;
    entity                *m_ent;
    unsigned              m_err_count;
    ucs_status_t          m_err_status;
    bool                  m_has_conn_timeout;
    std::vector<uct_ep_h> m_err_eps;
    std::vector<int>      m_raw_fds;
};

const double test_uct_tcp_explore_timeout_race::CONN_TIMEOUT_SEC = 0.2;
const double test_uct_tcp_explore_timeout_race::WAIT_TIMEOUT_SEC = 10.0;
const char *test_uct_tcp_explore_timeout_race::CONN_TIMEOUT_STR  = "200ms";


/* (1) EP stalls in WAITING_ACK, the deadline passes without progress, then a
 * valid CONN_ACK becomes readable BEFORE the single progress call: event
 * handling runs before the timeout sweep, so the ACK must win. */
UCS_TEST_P(test_uct_tcp_explore_timeout_race, ack_readable_before_sweep_wins)
{
    struct sockaddr_storage listen_addr;
    uct_tcp_cm_conn_req_pkt_t req;
    size_t fd_count;

    fd_count      = open_fd_count();
    int listen_fd = raw_listener(&listen_addr);

    ucs_time_t armed_at = ucs_get_time();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
    int peer_fd = raw_accept(listen_fd);
    raw_recv_conn_req(peer_fd, &req);

    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_iface_flush(m_ent->iface(), 0, NULL));

    pass_deadline_without_progress(armed_at);
    raw_send_conn_ack(peer_fd);
    EXPECT_GT(progress_once(), 0u);

    check_connected_ep(ep);
    check_send_works(ep, peer_fd);

    /* no late timeout */
    progress_for(2 * CONN_TIMEOUT_SEC);
    check_connected_ep(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_TRUE(raw_wait_peer_closed(peer_fd));
    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (2) Same stall, but progress runs once BEFORE the ACK is written: the EP
 * is failed by the timeout; a CONN_ACK arriving afterwards must be ignored
 * (events == 0 so it is never read), the EP stays CLOSED and the error
 * callback fires exactly once. */
UCS_TEST_P(test_uct_tcp_explore_timeout_race, ack_after_sweep_is_ignored)
{
    struct sockaddr_storage listen_addr;
    uct_tcp_cm_conn_req_pkt_t req;
    size_t fd_count;

    require_conn_timeout();

    fd_count      = open_fd_count();
    int listen_fd = raw_listener(&listen_addr);

    ucs_time_t armed_at = ucs_get_time();
    uct_ep_h ep = create_ep_to_port(port_of((struct sockaddr*)&listen_addr));
    int peer_fd = raw_accept(listen_fd);
    raw_recv_conn_req(peer_fd, &req);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_WAITING_ACK, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);

    pass_deadline_without_progress(armed_at);
    {
        scoped_log_handler slh(wrap_errors_logger);
        EXPECT_GT(progress_once(), 0u);
    }
    check_failed_ep(ep);
    EXPECT_EQ(-1, tcp_ep(ep)->stale_fd);

    /* late ACK: must not revive the EP */
    raw_send_conn_ack(peer_fd);
    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_EQ(UCS_ERR_CONNECTION_RESET,
              uct_ep_am_short(ep, TEST_AM_ID, 0, NULL, 0));
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    /* the failed EP keeps its socket until destroyed, then the peer sees
     * the close and no fd leaks */
    EXPECT_NE(-1, tcp_ep(ep)->fd);
    uct_ep_destroy(ep);
    EXPECT_TRUE(raw_wait_peer_closed(peer_fd));
    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (3) CONNECT_TO_EP, accept side: the user EP times out in ACCEPTING, then
 * the peer sends magic + CONN_REQ(CONNECT_TO_EP, our ptr map key). The EP
 * must already be off the ptr map, so the internal EP is dropped, the user
 * EP stays CLOSED, and the error callback fired exactly once. */
UCS_TEST_P(test_uct_tcp_explore_timeout_race, c2e_accepting_timeout_late_conn_req)
{
    struct sockaddr_storage peer_addr;
    size_t fd_count;

    require_conn_timeout();

    fd_count = open_fd_count();
    if (!raw_listener_lower(&peer_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    uct_ep_h ep = create_c2e_ep();
    ucs_ptr_map_key_t key = ptr_map_key(ep);
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);

    ucs_time_t armed_at = ucs_get_time();
    c2e_connect_accept_side(ep, (struct sockaddr*)&peer_addr);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_ACCEPTING, conn_state(ep));
    EXPECT_EQ(1u, m_tcp_iface->outstanding);
    EXPECT_EQ(1u, ep_count());

    pass_deadline_without_progress(armed_at);
    {
        scoped_log_handler slh(wrap_errors_logger);
        EXPECT_GT(progress_once(), 0u);
    }
    check_failed_ep(ep);
    EXPECT_TRUE(uct_tcp_ep_ptr_map_retrieve(m_tcp_iface, key) == NULL);

    /* late CONN_REQ from the peer for the failed EP */
    int peer_fd = raw_connect(iface_addr());
    raw_send_c2e_conn_req(peer_fd, key, (struct sockaddr*)&peer_addr);

    /* the internal EP accepted by the async thread must be created and then
     * destroyed again, since the ptr map lookup fails */
    EXPECT_TRUE(raw_wait_peer_closed(peer_fd));
    wait_for_ep_count(1);
    EXPECT_EQ(1u, ep_count());
    EXPECT_EQ(0u, ep_count_in_state(UCT_TCP_EP_CONN_STATE_ACCEPTING));
    EXPECT_EQ(0u, ep_count_in_state(UCT_TCP_EP_CONN_STATE_RECV_MAGIC_NUMBER));

    progress_for(2 * CONN_TIMEOUT_SEC);
    EXPECT_EQ(1u, m_err_count);
    EXPECT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, tcp_ep(ep)->events);
    EXPECT_EQ(-1, tcp_ep(ep)->fd);
    EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CTX_TYPE_RX);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_UCS_OK(uct_iface_flush(m_ent->iface(), 0, NULL));

    uct_ep_destroy(ep);
    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

/* (4) CONN_REQ for a CONNECT_TO_EP EP which is still CLOSED (connect_to_ep
 * not called yet) with a small timeout configured: CLOSED -> CONNECTED
 * directly, nothing is armed (outstanding stays 0) and no timeout ever
 * fires. The later uct_ep_connect_to_ep() is a no-op. */
UCS_TEST_P(test_uct_tcp_explore_timeout_race, c2e_early_conn_req_closed_to_connected)
{
    struct sockaddr_storage peer_addr;
    size_t fd_count;

    fd_count = open_fd_count();
    if (!raw_listener_lower(&peer_addr)) {
        UCS_TEST_SKIP_R("could not get a peer port lower than the iface port");
    }

    uct_ep_h ep = create_c2e_ep();
    ucs_ptr_map_key_t key = ptr_map_key(ep);
    ASSERT_EQ(UCT_TCP_EP_CONN_STATE_CLOSED, conn_state(ep));
    EXPECT_EQ(0u, m_tcp_iface->outstanding);

    int peer_fd = raw_connect(iface_addr());
    raw_send_c2e_conn_req(peer_fd, key, (struct sockaddr*)&peer_addr);

    wait_for_conn_state(ep, UCT_TCP_EP_CONN_STATE_CONNECTED);
    check_connected_ep(ep);
    EXPECT_FALSE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_ON_PTR_MAP);
    EXPECT_TRUE(tcp_ep(ep)->flags & UCT_TCP_EP_FLAG_CTX_TYPE_RX);
    wait_for_ep_count(1);
    EXPECT_EQ(1u, ep_count());

    /* the user now calls connect_to_ep: must be accepted as already done */
    c2e_connect_accept_side(ep, (struct sockaddr*)&peer_addr);
    check_connected_ep(ep);
    check_send_works(ep, peer_fd);

    /* a timeout, if configured, must never fire for this EP */
    progress_for(2 * CONN_TIMEOUT_SEC);
    check_connected_ep(ep);

    uct_ep_destroy(ep);
    EXPECT_EQ(0u, m_tcp_iface->outstanding);
    EXPECT_TRUE(raw_wait_peer_closed(peer_fd));
    close_fds(m_raw_fds);
    EXPECT_EQ(fd_count, open_fd_count());
}

_UCT_INSTANTIATE_TEST_CASE(test_uct_tcp_explore_timeout_race, tcp)
