/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2026. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

/*
 * Exploration tests for UCP endpoints whose TCP lanes time out while the
 * connection handshake is stalled (UCX_TCP_CONN_TIMEOUT). The stalled peer is
 * a raw socket that accepts the TCP connection but never speaks the UCT TCP
 * protocol, so the sender EP stays in WAITING_ACK until the timeout expires.
 */

#include "ucp_test.h"

extern "C" {
#include <ucp/core/ucp_context.h>
#include <ucp/core/ucp_worker.h>
#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_ep.inl>
#include <uct/tcp/tcp.h>
#include <ucs/config/parser.h>
#include <ucs/sys/sock.h>
}

#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>


class test_ucp_tcp_lane_timeout_base : public ucp_test {
public:
    enum {
        CLOSE_DEFAULT,
        CLOSE_FORCE
    };

    static void get_test_variants(std::vector<ucp_test_variant>& variants)
    {
        add_variant_with_value(variants, UCP_FEATURE_AM, CLOSE_DEFAULT,
                               "close");
        add_variant_with_value(variants, UCP_FEATURE_AM, CLOSE_FORCE,
                               "force_close");
    }

    test_ucp_tcp_lane_timeout_base() :
        m_err_count(0), m_err_status(UCS_OK), m_err_ep(NULL), m_am_rx(0)
    {
    }

    virtual ucp_ep_params_t get_ep_params()
    {
        ucp_ep_params_t params = ucp_test::get_ep_params();
        params.field_mask     |= UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLER;
        params.err_mode        = UCP_ERR_HANDLING_MODE_PEER;
        params.err_handler.cb  = err_cb;
        params.err_handler.arg = reinterpret_cast<void*>(this);
        return params;
    }

    virtual void cleanup()
    {
        close_raw_fds();
        ucp_test::cleanup();
    }

protected:
    static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
    {
        test_ucp_tcp_lane_timeout_base *self =
                reinterpret_cast<test_ucp_tcp_lane_timeout_base*>(arg);
        self->m_err_status = status;
        self->m_err_ep     = ep;
        ++self->m_err_count;
    }

    static ucs_status_t am_cb(void *arg, const void *header,
                              size_t header_length, void *data, size_t length,
                              const ucp_am_recv_param_t *param)
    {
        test_ucp_tcp_lane_timeout_base *self =
                reinterpret_cast<test_ucp_tcp_lane_timeout_base*>(arg);
        EXPECT_FALSE(param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV);
        ++self->m_am_rx;
        return UCS_OK;
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

    uint32_t close_flags() const
    {
        return (get_variant_value() == CLOSE_FORCE) ? UCP_EP_CLOSE_FLAG_FORCE :
                                                      0;
    }

    /* connection-establishment states (same on master and on the PR) */
    static bool conn_in_progress(const uct_tcp_ep_t *ep)
    {
        return (ep->conn_state == UCT_TCP_EP_CONN_STATE_CONNECTING) ||
               (ep->conn_state == UCT_TCP_EP_CONN_STATE_WAITING_ACK) ||
               (ep->conn_state == UCT_TCP_EP_CONN_STATE_ACCEPTING);
    }

    bool conn_timeout_supported() const
    {
        return ucs_config_global_list_has_field("TCP_CONN_TIMEOUT");
    }

    void skip_if_no_conn_timeout()
    {
        if (!conn_timeout_supported()) {
            UCS_TEST_SKIP_R("TCP_CONN_TIMEOUT is not a valid configuration");
        }
    }

    std::vector<uct_tcp_iface_t*> tcp_ifaces(const entity& e)
    {
        std::vector<uct_tcp_iface_t*> result;
        ucp_worker_h worker = e.worker();

        for (unsigned i = 0; i < worker->num_ifaces; ++i) {
            ucp_worker_iface_t *wiface = worker->ifaces[i];
            const uct_tl_resource_desc_t *rsc =
                    &worker->context->tl_rscs[wiface->rsc_index].tl_rsc;
            if ((wiface->iface != NULL) &&
                !strcmp(rsc->tl_name, UCT_TCP_NAME)) {
                result.push_back(ucs_derived_of(wiface->iface,
                                                uct_tcp_iface_t));
            }
        }

        EXPECT_FALSE(result.empty());
        return result;
    }

    unsigned tcp_outstanding(const entity& e)
    {
        std::vector<uct_tcp_iface_t*> ifaces = tcp_ifaces(e);
        unsigned outstanding                 = 0;

        for (size_t i = 0; i < ifaces.size(); ++i) {
            outstanding += ifaces[i]->outstanding;
        }
        return outstanding;
    }

    /* Number of EPs on the tcp ifaces' ep_list (EPs still on the connection
     * matching context are not visible here, but they are accounted for in
     * iface->outstanding while connecting) */
    size_t tcp_ep_list_count(const entity& e, bool in_progress_only = false)
    {
        std::vector<uct_tcp_iface_t*> ifaces = tcp_ifaces(e);
        size_t count                         = 0;
        uct_tcp_ep_t *ep;

        for (size_t i = 0; i < ifaces.size(); ++i) {
            UCS_ASYNC_BLOCK(ifaces[i]->super.worker->async);
            ucs_list_for_each(ep, &ifaces[i]->ep_list, list) {
                if (!in_progress_only || conn_in_progress(ep)) {
                    ++count;
                }
            }
            UCS_ASYNC_UNBLOCK(ifaces[i]->super.worker->async);
        }
        return count;
    }

    void check_tcp_ifaces_idle(const entity& e)
    {
        std::vector<uct_tcp_iface_t*> ifaces = tcp_ifaces(e);

        EXPECT_EQ(0u, tcp_outstanding(e));
        for (size_t i = 0; i < ifaces.size(); ++i) {
            EXPECT_UCS_OK(uct_iface_flush(&ifaces[i]->super.super, 0, NULL));
            uct_tcp_ep_t *ep;
            UCS_ASYNC_BLOCK(ifaces[i]->super.worker->async);
            ucs_list_for_each(ep, &ifaces[i]->ep_list, list) {
                EXPECT_FALSE(conn_in_progress(ep))
                        << "ep state " << ep->conn_state;
                EXPECT_EQ(-1, ep->stale_fd);
            }
            UCS_ASYNC_UNBLOCK(ifaces[i]->super.worker->async);
        }
    }

    void progress_sender_for(double seconds)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(seconds) * ucs::test_time_multiplier();
        while (ucs_get_time() < deadline) {
            sender().progress();
        }
    }

    template<typename Pred>
    void progress_sender_until(const Pred& pred, double timeout = 20.0)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(timeout) * ucs::test_time_multiplier();
        while (!pred() && (ucs_get_time() < deadline)) {
            sender().progress();
        }
    }

    struct err_count_reached {
        err_count_reached(const test_ucp_tcp_lane_timeout_base& t, unsigned n) :
            m_t(t), m_n(n) {}
        bool operator()() const { return m_t.m_err_count >= m_n; }
        const test_ucp_tcp_lane_timeout_base& m_t;
        unsigned m_n;
    };

    struct outstanding_is_zero {
        outstanding_is_zero(test_ucp_tcp_lane_timeout_base& t) : m_t(t) {}
        bool operator()() const {
            return (m_t.tcp_outstanding(m_t.sender()) == 0) &&
                   (m_t.tcp_ep_list_count(m_t.sender()) == 0);
        }
        test_ucp_tcp_lane_timeout_base& m_t;
    };

    /*
     * Replace the receiver with raw listeners bound to the exact ip:port of
     * every tcp iface of the receiver worker. The listeners accept TCP
     * connections (kernel completes the 3-way handshake, backlog) but never
     * read or write, so the UCT TCP CONN_REQ sent by the sender is never
     * acknowledged and the sender EP is stuck in WAITING_ACK.
     */
    void stall_receiver()
    {
        std::vector<uct_tcp_iface_t*> ifaces = tcp_ifaces(receiver());
        std::vector<struct sockaddr_storage> addrs;
        ucp_address_t *address;
        size_t address_length;

        for (size_t i = 0; i < ifaces.size(); ++i) {
            struct sockaddr_storage saddr;
            memcpy(&saddr, &ifaces[i]->config.ifaddr, sizeof(saddr));
            addrs.push_back(saddr);
        }

        ASSERT_UCS_OK(ucp_worker_get_address(receiver().worker(), &address,
                                             &address_length));
        m_saved_address.assign(reinterpret_cast<const char*>(address),
                               reinterpret_cast<const char*>(address) +
                               address_length);
        ucp_worker_release_address(receiver().worker(), address);

        /* Destroy the receiver worker/listeners so the ports become free */
        receiver().cleanup();

        for (size_t i = 0; i < addrs.size(); ++i) {
            raw_listener(addrs[i]);
        }
    }

    void raw_listener(const struct sockaddr_storage& addr)
    {
        size_t addr_size;
        int fd, reuse = 1;

        ASSERT_UCS_OK(ucs_sockaddr_sizeof((const struct sockaddr*)&addr,
                                          &addr_size));
        ASSERT_UCS_OK(ucs_socket_create(addr.ss_family, SOCK_STREAM, 0, &fd));
        m_raw_fds.push_back(fd);
        EXPECT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                                sizeof(reuse)));
        if (bind(fd, (const struct sockaddr*)&addr, addr_size) != 0) {
            UCS_TEST_SKIP_R(std::string("cannot rebind receiver address: ") +
                            strerror(errno));
        }
        EXPECT_EQ(0, listen(fd, 128));
    }

    void close_raw_fds()
    {
        for (size_t i = 0; i < m_raw_fds.size(); ++i) {
            close(m_raw_fds[i]);
        }
        m_raw_fds.clear();
    }

    ucp_ep_h create_ep_to_saved_address()
    {
        ucp_ep_params_t params = get_ep_params();
        ucp_ep_h ep;

        params.field_mask |= UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
        params.address     = reinterpret_cast<const ucp_address_t*>(
                                     &m_saved_address[0]);
        ASSERT_UCS_OK(ucp_ep_create(sender().worker(), &params, &ep));
        return ep;
    }

    void *am_send(ucp_ep_h ep)
    {
        ucp_request_param_t param;

        param.op_attr_mask = 0;
        return ucp_am_send_nbx(ep, 0, NULL, 0, &m_send_buf[0],
                               m_send_buf.size(), &param);
    }

    void set_am_handler(entity& e)
    {
        ucp_am_handler_param_t param;

        param.field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
                           UCP_AM_HANDLER_PARAM_FIELD_CB |
                           UCP_AM_HANDLER_PARAM_FIELD_ARG;
        param.id         = 0;
        param.cb         = am_cb;
        param.arg        = this;
        ASSERT_UCS_OK(ucp_worker_set_am_recv_handler(e.worker(), &param));
    }

    void close_ep(ucp_ep_h ep, uint32_t flags, const std::string& what)
    {
        void *req           = ep_close_nbx(ep, flags);
        ucs_status_t status = request_wait(req, {&sender()});
        EXPECT_NE(UCS_INPROGRESS, status) << what << " close did not complete";
    }

    void init_send_buf()
    {
        m_send_buf.resize(64, 'x');
    }

    /* Common body of the stalled-peer tests: wireup never completes, the
     * connection timeout must fail the UCP EP exactly once and everything
     * must be released */
    void do_stalled_timeout()
    {
        scoped_log_handler slh(wrap_errors_logger);

        init_send_buf();
        stall_receiver();

        const size_t fd_baseline = open_fd_count();
        ucp_ep_h ep              = create_ep_to_saved_address();
        void *sreq               = am_send(ep);

        EXPECT_TRUE(UCS_PTR_IS_PTR(sreq) || (sreq == NULL))
                << ucs_status_string(UCS_PTR_STATUS(sreq));

        /* The wireup created at least one tcp EP which is now connecting to
         * the raw listener */
        EXPECT_GE(tcp_outstanding(sender()), 1u);

        /* tmo:expire_user_ep / conn:WAITING_ACK->CLOSED_timeout */
        progress_sender_until(err_count_reached(*this, 1));
        ASSERT_EQ(1u, m_err_count) << "UCP error callback did not fire";
        EXPECT_EQ(ep, m_err_ep);
        EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT, m_err_status)
                << ucs_status_string(m_err_status);

        /* failed:user_ep_sync_error - the posted send must fail */
        if (UCS_PTR_IS_PTR(sreq)) {
            ucs_status_t sstatus = request_wait(sreq, {&sender()});
            EXPECT_NE(UCS_OK, sstatus);
            EXPECT_NE(UCS_INPROGRESS, sstatus) << "send request never completed";
            UCS_TEST_MESSAGE << "send request status: "
                             << ucs_status_string(sstatus);
        }

        /* out:dec_inprogress->CLOSED - the failed lanes are discarded and
         * destroyed, outstanding returns to 0 */
        progress_sender_until(outstanding_is_zero(*this));
        check_tcp_ifaces_idle(sender());
        EXPECT_EQ(0u, tcp_ep_list_count(sender()));

        EXPECT_UCS_OK(request_wait(sender().flush_worker_nb(), {&sender()}));

        close_ep(ep, close_flags(), "ep");

        /* nothing left armed: no late callback */
        progress_sender_for(0.6);
        EXPECT_EQ(1u, m_err_count);

        check_tcp_ifaces_idle(sender());
        EXPECT_EQ(0u, tcp_ep_list_count(sender()));
        EXPECT_UCS_OK(request_wait(sender().flush_worker_nb(), {&sender()}));
        EXPECT_EQ(fd_baseline, open_fd_count());
    }

    unsigned                     m_err_count;
    ucs_status_t                 m_err_status;
    ucp_ep_h                     m_err_ep;
    unsigned                     m_am_rx;
    std::vector<int>             m_raw_fds;
    std::vector<char>            m_saved_address;
    std::vector<char>            m_send_buf;
};


/* TCP_CONN_TIMEOUT=200ms */
class test_ucp_explore_ucp_wireup_tcp_lane_timeout :
        public test_ucp_tcp_lane_timeout_base {
public:
    virtual void init()
    {
        modify_config("TCP_CONN_TIMEOUT", "200ms", IGNORE_IF_NOT_EXIST);
        test_ucp_tcp_lane_timeout_base::init();
    }
};

UCS_TEST_P(test_ucp_explore_ucp_wireup_tcp_lane_timeout, stalled_peer_timeout)
{
    skip_if_no_conn_timeout();
    do_stalled_timeout();
}

UCS_TEST_P(test_ucp_explore_ucp_wireup_tcp_lane_timeout,
           stalled_peer_timeout_keepalive, "KEEPALIVE_INTERVAL=0.1",
           "KEEPALIVE_NUM_EPS=inf")
{
    skip_if_no_conn_timeout();
    do_stalled_timeout();
}

/* Control: a live receiver with the same timeout - wireup completes, no
 * error callback, nothing in progress on the tcp ifaces afterwards */
UCS_TEST_P(test_ucp_explore_ucp_wireup_tcp_lane_timeout, live_peer_control)
{
    init_send_buf();
    set_am_handler(receiver());
    sender().connect(&receiver(), get_ep_params());

    void *sreq = am_send(sender().ep());
    EXPECT_UCS_OK(request_wait(sreq));
    while (m_am_rx < 1) {
        progress();
    }

    EXPECT_UCS_OK(request_wait(sender().flush_worker_nb()));
    EXPECT_UCS_OK(request_wait(receiver().flush_worker_nb()));
    check_tcp_ifaces_idle(sender());
    check_tcp_ifaces_idle(receiver());

    /* progress for several timeouts: nothing must expire */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(0.6) *
                                           ucs::test_time_multiplier();
    while (ucs_get_time() < deadline) {
        progress();
    }
    EXPECT_EQ(0u, m_err_count);

    /* the EP is still usable */
    sreq = am_send(sender().ep());
    EXPECT_UCS_OK(request_wait(sreq));
    while (m_am_rx < 2) {
        progress();
    }
    EXPECT_EQ(0u, m_err_count);

    void *creq = ep_close_nbx(sender().ep(), close_flags());
    EXPECT_NE(UCS_INPROGRESS, request_wait(creq));
    sender().revoke_ep(0, 0);
    EXPECT_EQ(0u, m_err_count);
}

UCP_INSTANTIATE_TEST_CASE_TLS(test_ucp_explore_ucp_wireup_tcp_lane_timeout,
                              tcp, "tcp")


/* Default config (TCP_CONN_TIMEOUT=inf): a stalled peer never produces an
 * error, the EP stays in progress and only a forced close releases it.
 * Identical expectations on master and on the PR branch. */
class test_ucp_explore_ucp_wireup_tcp_lane_timeout_inf :
        public test_ucp_tcp_lane_timeout_base {
public:
    static void get_test_variants(std::vector<ucp_test_variant>& variants)
    {
        add_variant_with_value(variants, UCP_FEATURE_AM, CLOSE_FORCE,
                               "force_close");
    }
};

UCS_TEST_P(test_ucp_explore_ucp_wireup_tcp_lane_timeout_inf,
           stalled_peer_no_timeout_force_close)
{
    scoped_log_handler slh(wrap_errors_logger);

    init_send_buf();
    stall_receiver();

    const size_t fd_baseline = open_fd_count();
    ucp_ep_h ep              = create_ep_to_saved_address();
    void *sreq               = am_send(ep);

    EXPECT_TRUE(UCS_PTR_IS_PTR(sreq) || (sreq == NULL));
    EXPECT_GE(tcp_outstanding(sender()), 1u);

    /* well beyond any finite timeout used by the other tests */
    progress_sender_for(0.6);
    EXPECT_EQ(0u, m_err_count);
    EXPECT_GE(tcp_outstanding(sender()), 1u);

    close_ep(ep, UCP_EP_CLOSE_FLAG_FORCE, "forced");
    if (UCS_PTR_IS_PTR(sreq)) {
        ucs_status_t sstatus = request_wait(sreq, {&sender()});
        EXPECT_NE(UCS_OK, sstatus);
        EXPECT_NE(UCS_INPROGRESS, sstatus) << "send request never completed";
    }

    progress_sender_until(outstanding_is_zero(*this));
    check_tcp_ifaces_idle(sender());
    EXPECT_EQ(0u, tcp_ep_list_count(sender()));
    EXPECT_UCS_OK(request_wait(sender().flush_worker_nb(), {&sender()}));
    EXPECT_EQ(fd_baseline, open_fd_count());
    EXPECT_EQ(0u, m_err_count);
}

UCP_INSTANTIATE_TEST_CASE_TLS(test_ucp_explore_ucp_wireup_tcp_lane_timeout_inf,
                              tcp, "tcp")
