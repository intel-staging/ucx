/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ze_ipc_ep.h"
#include "ze_ipc_cache.h"
#include "ze_ipc_iface.h"
#include "ze_ipc_md.h"

#include <uct/base/uct_log.h>
#include <uct/base/uct_iov.inl>
#include <ucs/debug/memtrack_int.h>
#include <ucs/type/class.h>
#include <ucs/profile/profile.h>

#include <string.h>
#include <sys/types.h>


#define UCT_ZE_IPC_PUT 0
#define UCT_ZE_IPC_GET 1


typedef struct uct_ze_ipc_ep {
    uct_base_ep_t super;
    pid_t         remote_pid;
} uct_ze_ipc_ep_t;


static UCS_CLASS_INIT_FUNC(uct_ze_ipc_ep_t, const uct_ep_params_t *params)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(params->iface,
                                               uct_ze_ipc_iface_t);

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);
    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

    self->remote_pid = *(const pid_t*)params->iface_addr;

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ze_ipc_ep_t)
{
}

UCS_CLASS_DEFINE(uct_ze_ipc_ep_t, uct_base_ep_t)
UCS_CLASS_DEFINE_NEW_FUNC(uct_ze_ipc_ep_t, uct_ep_t, const uct_ep_params_t*);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_ze_ipc_ep_t, uct_ep_t);

int uct_ze_ipc_ep_is_connected(const uct_ep_h tl_ep,
                               const uct_ep_is_connected_params_t *params)
{
    const uct_ze_ipc_ep_t *ep = ucs_derived_of(tl_ep, uct_ze_ipc_ep_t);

    if (!uct_base_ep_is_connected(tl_ep, params)) {
        return 0;
    }

    return ep->remote_pid == *(pid_t*)params->iface_addr;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_ze_ipc_post_copy(uct_ep_h tl_ep, uint64_t remote_addr, const uct_iov_t *iov,
                     uct_rkey_t rkey, uct_completion_t *comp, int direction)
{
    uct_ze_ipc_iface_t *iface            = ucs_derived_of(tl_ep->iface,
                                                          uct_ze_ipc_iface_t);
    uct_ze_ipc_ep_t *ep                  = ucs_derived_of(tl_ep,
                                                          uct_ze_ipc_ep_t);
    uct_ze_ipc_unpacked_rkey_t *unpacked = (uct_ze_ipc_unpacked_rkey_t*)rkey;
    ze_event_pool_desc_t event_pool_desc = {};
    ze_event_desc_t event_desc_ze        = {};
    void *mapped_addr                    = NULL;
    uct_ze_ipc_queue_desc_t *q_desc;
    uct_ze_ipc_event_desc_t *event_desc;
    ucs_status_t status;
    void *mapped_rem_addr;
    void *dst, *src;
    size_t offset;
    size_t length;
    unsigned cmd_list_idx;
    int local_fd;

    length = uct_iov_get_length(iov);
    if (ucs_unlikely(length == 0)) {
        return UCS_OK;
    }

    /* Map IPC handle using cache */
    status = uct_ze_ipc_map_memhandle(iface, &unpacked->super,
                                      iface->ze_context, iface->ze_device,
                                      &mapped_addr, &local_fd);
    if (status != UCS_OK) {
        ucs_error("failed to map ze ipc handle for addr 0x%lx pid %d: %s",
                  unpacked->super.d_bptr, ep->remote_pid,
                  ucs_status_string(status));
        return status;
    }

    /* Calculate offset within the allocation */
    offset          = remote_addr - unpacked->super.d_bptr;
    mapped_rem_addr = (void*)((uintptr_t)mapped_addr + offset);

    /* Allocate event descriptor - zero-initialize to ensure cleanup safety */
    event_desc = ucs_calloc(1, sizeof(*event_desc), "uct_ze_ipc_event_desc_t");
    if (event_desc == NULL) {
        ucs_error("failed to allocate ze ipc event descriptor");
        status = UCS_ERR_NO_MEMORY;
        goto err_unmap;
    }

    /* Initialize all fields for safe cleanup */
    event_desc->dup_fd      = local_fd;
    event_desc->pid         = ep->remote_pid;
    event_desc->address     = unpacked->super.d_bptr;
    event_desc->mapped_addr = mapped_addr;
    event_desc->comp        = comp;

    /* Create event pool for tracking */
    event_pool_desc.stype = ZE_STRUCTURE_TYPE_EVENT_POOL_DESC;
    event_pool_desc.count = 1;
    event_pool_desc.flags = ZE_EVENT_POOL_FLAG_HOST_VISIBLE;

    status = UCT_ZE_FUNC_LOG_ERR(
            zeEventPoolCreate(iface->ze_context, &event_pool_desc, 1,
                              &iface->ze_device, &event_desc->event_pool));
    if (status != UCS_OK) {
        status = UCS_ERR_IO_ERROR;
        goto err_free_desc;
    }

    /* Initialize event descriptor */
    memset(&event_desc_ze, 0, sizeof(event_desc_ze));
    event_desc_ze.stype  = ZE_STRUCTURE_TYPE_EVENT_DESC;
    event_desc_ze.index  = 0;
    event_desc_ze.signal = ZE_EVENT_SCOPE_FLAG_HOST;
    event_desc_ze.wait   = ZE_EVENT_SCOPE_FLAG_HOST;

    status = UCT_ZE_FUNC_LOG_ERR(zeEventCreate(event_desc->event_pool,
                                               &event_desc_ze,
                                               &event_desc->event));
    if (status != UCS_OK) {
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_pool;
    }

    /* Select command list deterministically from rkey for ordering */
    cmd_list_idx = unpacked->cmd_list_id % iface->num_cmd_lists;
    q_desc       = &iface->queue_desc[cmd_list_idx];

    /* Set up source and destination */
    if (direction == UCT_ZE_IPC_PUT) {
        dst = mapped_rem_addr;
        src = iov->buffer;
    } else {
        dst = iov->buffer;
        src = mapped_rem_addr;
    }

    /* Append copy to immediate command list */
    status = UCT_ZE_FUNC_LOG_ERR(
            zeCommandListAppendMemoryCopy(q_desc->cmd_list, dst, src, length,
                                          event_desc->event, 0, NULL));
    if (status != UCS_OK) {
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_event;
    }

    /* Add to active queue if first event for this cmd list */
    if (ucs_queue_is_empty(&q_desc->event_queue)) {
        ucs_queue_push(&iface->active_queue, &q_desc->queue);
    }

    /* Push event to queue */
    ucs_queue_push(&q_desc->event_queue, &event_desc->queue);

    ucs_trace("ze_ipc: %s issued len=%zu cmd_list=%u",
              (direction == UCT_ZE_IPC_PUT) ? "PUT" : "GET", length,
              cmd_list_idx);

    return UCS_INPROGRESS;

err_destroy_event:
    zeEventDestroy(event_desc->event);
err_destroy_pool:
    zeEventPoolDestroy(event_desc->event_pool);
err_free_desc:
    ucs_free(event_desc);
err_unmap:
    uct_ze_ipc_unmap_memhandle(ep->remote_pid, unpacked->super.d_bptr,
                               mapped_addr, iface->ze_context, local_fd,
                               iface->config.enable_cache);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_ze_ipc_ep_get_zcopy,
                 (tl_ep, iov, iovcnt, remote_addr, rkey, comp), uct_ep_h tl_ep,
                 const uct_iov_t *iov, size_t iovcnt, uint64_t remote_addr,
                 uct_rkey_t rkey, uct_completion_t *comp)
{
    ucs_status_t status;

    status = uct_ze_ipc_post_copy(tl_ep, remote_addr, iov, rkey, comp,
                                  UCT_ZE_IPC_GET);
    if (UCS_STATUS_IS_ERR(status)) {
        return status;
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), GET, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    ucs_trace_data("GET_ZCOPY size %zu from %p",
                   uct_iov_total_length(iov, iovcnt), (void*)remote_addr);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_ze_ipc_ep_put_zcopy,
                 (tl_ep, iov, iovcnt, remote_addr, rkey, comp), uct_ep_h tl_ep,
                 const uct_iov_t *iov, size_t iovcnt, uint64_t remote_addr,
                 uct_rkey_t rkey, uct_completion_t *comp)
{
    ucs_status_t status;

    status = uct_ze_ipc_post_copy(tl_ep, remote_addr, iov, rkey, comp,
                                  UCT_ZE_IPC_PUT);
    if (UCS_STATUS_IS_ERR(status)) {
        return status;
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), PUT, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    ucs_trace_data("PUT_ZCOPY size %zu to %p",
                   uct_iov_total_length(iov, iovcnt), (void*)remote_addr);
    return status;
}
