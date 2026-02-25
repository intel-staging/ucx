/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ze_ipc_iface.h"
#include "ze_ipc_cache.h"
#include "ze_ipc_ep.h"

#include <ucs/async/eventfd.h>
#include <ucs/arch/atomic.h>
#include <ucs/datastruct/list.h>
#include <ucs/type/class.h>
#include <ucs/sys/string.h>

#include <unistd.h>
#include <sys/types.h>


#define UCT_ZE_IPC_PARALLEL_THRESHOLD 262144 /* 256KB */
#define UCT_ZE_IPC_TL_NAME            "ze_ipc"


static ucs_config_field_t uct_ze_ipc_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_ze_ipc_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {"MAX_POLL", "16",
     "Max number of event completions to pick during ze events polling",
     ucs_offsetof(uct_ze_ipc_iface_config_t, max_poll), UCS_CONFIG_TYPE_UINT},

    {"MAX_CMD_LISTS", UCS_PP_MAKE_STRING(UCT_ZE_IPC_MAX_CMD_LISTS),
     "Max number of command lists for concurrent progress",
     ucs_offsetof(uct_ze_ipc_iface_config_t, max_cmd_lists),
     UCS_CONFIG_TYPE_UINT},

    {"ENABLE_CACHE", "yes", "Enable IPC handle caching to improve performance",
     ucs_offsetof(uct_ze_ipc_iface_config_t, enable_cache),
     UCS_CONFIG_TYPE_BOOL},

    {"PARALLEL_THRESH", UCS_PP_MAKE_STRING(UCT_ZE_IPC_PARALLEL_THRESHOLD),
     "Size threshold below which to use round-robin (parallel) vs deterministic\n"
     "(cache-local). Small sizes benefit from parallelism; large from locality.",
     ucs_offsetof(uct_ze_ipc_iface_config_t, parallel_threshold),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"BW", "50000MBs", "Effective p2p memory bandwidth",
     ucs_offsetof(uct_ze_ipc_iface_config_t, bandwidth), UCS_CONFIG_TYPE_BW},

    {"LAT", "1.8us", "Estimated latency",
     ucs_offsetof(uct_ze_ipc_iface_config_t, latency), UCS_CONFIG_TYPE_TIME},

    {"OVERHEAD", "4.0us", "Estimated CPU overhead for transferring GPU memory",
     ucs_offsetof(uct_ze_ipc_iface_config_t, overhead), UCS_CONFIG_TYPE_TIME},

    {NULL}
};


/* Forward declaration */
static void UCS_CLASS_DELETE_FUNC_NAME(uct_ze_ipc_iface_t)(uct_iface_t*);

static ucs_status_t uct_ze_ipc_iface_get_device_address(uct_iface_t *tl_iface,
                                                        uct_device_addr_t *addr)
{
    *(uint64_t*)addr = ucs_get_system_id();
    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_iface_get_address(uct_iface_h tl_iface, uct_iface_addr_t *iface_addr)
{
    *(pid_t*)iface_addr = getpid();
    return UCS_OK;
}

static int
uct_ze_ipc_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                 const uct_iface_is_reachable_params_t *params)
{
    uint64_t *dev_addr;
    int same_uuid;

    if (!uct_iface_is_reachable_params_addrs_valid(params)) {
        return 0;
    }

    dev_addr  = (uint64_t*)params->device_addr;
    same_uuid = (ucs_get_system_id() == *dev_addr);

    if ((getpid() == *(pid_t*)params->iface_addr) && same_uuid) {
        uct_iface_fill_info_str_buf(params, "same process");
        return 0;
    }

    if (same_uuid) {
        return uct_iface_scope_is_reachable(tl_iface, params);
    }

    uct_iface_fill_info_str_buf(params, "different system");
    return 0;
}

static ucs_status_t
uct_ze_ipc_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_ze_ipc_iface_t);

    uct_base_iface_query(&iface->super, iface_attr);

    iface_attr->iface_addr_len          = sizeof(pid_t);
    iface_attr->device_addr_len         = sizeof(uint64_t);
    iface_attr->ep_addr_len             = 0;
    iface_attr->max_conn_priv           = 0;
    iface_attr->cap.flags               = 
            UCT_IFACE_FLAG_ERRHANDLE_PEER_FAILURE |
            UCT_IFACE_FLAG_CONNECT_TO_IFACE | UCT_IFACE_FLAG_PENDING |
            UCT_IFACE_FLAG_GET_ZCOPY | UCT_IFACE_FLAG_PUT_ZCOPY;
    iface_attr->cap.event_flags         = UCT_IFACE_FLAG_EVENT_SEND_COMP |
                                          UCT_IFACE_FLAG_EVENT_RECV |
                                          UCT_IFACE_FLAG_EVENT_FD;
    iface_attr->cap.put.max_short       = 0;
    iface_attr->cap.put.max_bcopy       = 0;
    iface_attr->cap.put.min_zcopy       = 0;
    iface_attr->cap.put.max_zcopy       = ULONG_MAX;
    iface_attr->cap.put.opt_zcopy_align = 1;
    iface_attr->cap.put.align_mtu       = iface_attr->cap.put.opt_zcopy_align;
    iface_attr->cap.put.max_iov         = 1;
    iface_attr->cap.get.max_short       = 0;
    iface_attr->cap.get.max_bcopy       = 0;
    iface_attr->cap.get.min_zcopy       = 0;
    iface_attr->cap.get.max_zcopy       = ULONG_MAX;
    iface_attr->cap.get.opt_zcopy_align = 1;
    iface_attr->cap.get.align_mtu       = iface_attr->cap.get.opt_zcopy_align;
    iface_attr->cap.get.max_iov         = 1;
    /* Latency and overhead don't depend on config values for
     * the sake of wire compatibility */
    iface_attr->latency                 = ucs_linear_func_make(1e-6, 0);
    iface_attr->bandwidth.dedicated     = 0;
    iface_attr->bandwidth.shared        = iface->config.bandwidth;
    iface_attr->overhead                = 7.0e-6;
    iface_attr->priority                = 0;

    return UCS_OK;
}

static unsigned
uct_ze_ipc_iface_progress_common(uct_ze_ipc_iface_t *iface, unsigned max_poll)
{
    unsigned count = 0;
    uct_ze_ipc_event_desc_t *event_desc;
    uct_ze_ipc_queue_desc_t *q_desc;
    ucs_queue_elem_t *queue_elem;
    ucs_queue_iter_t q_iter;
    ucs_list_link_t local_completed;
    ucs_status_t status;
    ze_result_t ret;
    unsigned start_idx;
    unsigned i;

    start_idx = ucs_atomic_fadd32(&iface->next_progress_idx, 1) %
                iface->num_cmd_lists;

    for (i = 0; (i < iface->num_cmd_lists) && (count < max_poll); i++) {
        q_desc = &iface->queue_desc[(start_idx + i) % iface->num_cmd_lists];
        ucs_list_head_init(&local_completed);

        ucs_recursive_spin_lock(&q_desc->lock);

        ucs_queue_for_each_safe(event_desc, q_iter, &q_desc->event_queue,
                                queue) {
            if (count >= max_poll) {
                break;
            }

            ret = zeEventQueryStatus(event_desc->event);
            if (ucs_unlikely((ret != ZE_RESULT_SUCCESS) &&
                             (ret != ZE_RESULT_NOT_READY))) {
                ucs_debug("zeEventQueryStatus failed: 0x%x, completing event", ret);
                ucs_queue_del_iter(&q_desc->event_queue, q_iter);
                q_desc->event_get_idx++;
                ucs_list_add_tail(&local_completed, &event_desc->list);
                count++;
                continue;
            }

            if (ret == ZE_RESULT_NOT_READY) {
                continue;
            }

            ucs_queue_del_iter(&q_desc->event_queue, q_iter);

            /* Recycle pre-created event slot */
            ret = zeEventHostReset(event_desc->event);
            if (ret != ZE_RESULT_SUCCESS) {
                ucs_debug("zeEventHostReset failed: 0x%x", ret);
            }

            q_desc->event_get_idx++;
            ucs_list_add_tail(&local_completed, &event_desc->list);

            count++;
        }

        ucs_recursive_spin_unlock(&q_desc->lock);

        while (!ucs_list_is_empty(&local_completed)) {
            event_desc = ucs_list_extract_head(&local_completed,
                                               uct_ze_ipc_event_desc_t, list);

            if (event_desc->mapped_addr != NULL) {
                status = uct_ze_ipc_unmap_memhandle(event_desc->pid,
                                                    event_desc->address,
                                                    event_desc->mapped_addr,
                                                    iface->ze_context,
                                                    event_desc->dup_fd,
                                                    iface->config.enable_cache);
                if (status != UCS_OK) {
                    ucs_warn("failed to unmap ipc handle addr: %p",
                             event_desc->mapped_addr);
                }
            }

            if (event_desc->comp != NULL) {
                uct_invoke_completion(event_desc->comp, UCS_OK);
            }

            ucs_recursive_spin_lock(&q_desc->lock);
            queue_elem = &event_desc->queue;
            queue_elem->next = NULL;
            ucs_queue_push(&q_desc->free_event_descs, queue_elem);
            ucs_recursive_spin_unlock(&q_desc->lock);
        }
    }

    return count;
}

static unsigned uct_ze_ipc_iface_progress(uct_iface_h tl_iface)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_ze_ipc_iface_t);

    return uct_ze_ipc_iface_progress_common(iface, iface->config.max_poll);
}

unsigned uct_ze_ipc_iface_progress_nudge(uct_ze_ipc_iface_t *iface,
                                         unsigned max_poll)
{
    if (max_poll == 0) {
        /* max_poll == 0 means: use iface default polling budget. */
        max_poll = iface->config.max_poll;
    }

    return uct_ze_ipc_iface_progress_common(iface, max_poll);
}

static ucs_status_t uct_ze_ipc_iface_flush(uct_iface_h tl_iface,
                                           unsigned flags,
                                           uct_completion_t *comp)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_ze_ipc_iface_t);
    unsigned i;

    /* Check if all command list queues are empty */
    for (i = 0; i < iface->num_cmd_lists; i++) {
        ucs_recursive_spin_lock(&iface->queue_desc[i].lock);
        if (!ucs_queue_is_empty(&iface->queue_desc[i].event_queue)) {
            ucs_recursive_spin_unlock(&iface->queue_desc[i].lock);
            UCT_TL_IFACE_STAT_FLUSH_WAIT(
                    ucs_derived_of(tl_iface, uct_base_iface_t));
            return UCS_INPROGRESS;
        }

        ucs_recursive_spin_unlock(&iface->queue_desc[i].lock);
    }

    UCT_TL_IFACE_STAT_FLUSH(ucs_derived_of(tl_iface, uct_base_iface_t));
    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_ze_ipc_iface_t);
    ucs_status_t status;

    if (iface->eventfd == UCS_ASYNC_EVENTFD_INVALID_FD) {
        status = ucs_async_eventfd_create(&iface->eventfd);
        if (status != UCS_OK) {
            return status;
        }
    }

    *fd_p = iface->eventfd;
    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_iface_event_arm(uct_iface_h tl_iface, unsigned events)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_ze_ipc_iface_t);
    uct_ze_ipc_queue_desc_t *q_desc;
    uct_ze_ipc_event_desc_t *event_desc;
    ucs_queue_iter_t q_iter;
    ucs_status_t status;
    ze_result_t ret;
    unsigned i;

    /* Check if any events are already complete */
    for (i = 0; i < iface->num_cmd_lists; i++) {
        q_desc = &iface->queue_desc[i];
        ucs_recursive_spin_lock(&q_desc->lock);
        ucs_queue_for_each_safe(event_desc, q_iter, &q_desc->event_queue,
                                queue) {
            ret = zeEventQueryStatus(event_desc->event);
            if (ret != ZE_RESULT_NOT_READY) {
                ucs_recursive_spin_unlock(&q_desc->lock);
                return UCS_ERR_BUSY;
            }
        }
        ucs_recursive_spin_unlock(&q_desc->lock);
    }

    /* Clear any pending signals */
    if (iface->eventfd != UCS_ASYNC_EVENTFD_INVALID_FD) {
        status = ucs_async_eventfd_poll(iface->eventfd);
        if (status == UCS_OK) {
            return UCS_ERR_BUSY;
        }
    }

    return UCS_OK;
}

static uct_iface_ops_t uct_ze_ipc_iface_ops = {
    .ep_get_zcopy             = uct_ze_ipc_ep_get_zcopy,
    .ep_put_zcopy             = uct_ze_ipc_ep_put_zcopy,
    .ep_pending_add           = (uct_ep_pending_add_func_t)
            ucs_empty_function_return_busy,
    .ep_pending_purge         = (uct_ep_pending_purge_func_t)
            ucs_empty_function,
    .ep_flush                 = uct_base_ep_flush,
    .ep_fence                 = uct_base_ep_fence,
    .ep_check                 = (uct_ep_check_func_t)
            ucs_empty_function_return_unsupported,
    .ep_create                = UCS_CLASS_NEW_FUNC_NAME(uct_ze_ipc_ep_t),
    .ep_destroy               = UCS_CLASS_DELETE_FUNC_NAME(uct_ze_ipc_ep_t),
    .iface_flush              = uct_ze_ipc_iface_flush,
    .iface_fence              = uct_base_iface_fence,
    .iface_progress_enable    = uct_base_iface_progress_enable,
    .iface_progress_disable   = uct_base_iface_progress_disable,
    .iface_progress           = uct_ze_ipc_iface_progress,
    .iface_event_fd_get       = uct_ze_ipc_iface_event_fd_get,
    .iface_event_arm          = uct_ze_ipc_iface_event_arm,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(
            uct_ze_ipc_iface_t),
    .iface_query              = uct_ze_ipc_iface_query,
    .iface_get_device_address = uct_ze_ipc_iface_get_device_address,
    .iface_get_address        = uct_ze_ipc_iface_get_address,
    .iface_is_reachable       = uct_base_iface_is_reachable,
};

static ucs_status_t
uct_ze_ipc_estimate_perf(uct_iface_h tl_iface, uct_perf_attr_t *perf_attr)
{
    uct_ze_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_ze_ipc_iface_t);

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_BANDWIDTH) {
        perf_attr->bandwidth.dedicated = 0;
        perf_attr->bandwidth.shared    = iface->config.bandwidth;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_PATH_BANDWIDTH) {
        perf_attr->path_bandwidth.dedicated = 0;
        perf_attr->path_bandwidth.shared    = iface->config.bandwidth;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_SEND_PRE_OVERHEAD) {
        perf_attr->send_pre_overhead = iface->config.overhead;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_SEND_POST_OVERHEAD) {
        perf_attr->send_post_overhead = 0;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_RECV_OVERHEAD) {
        perf_attr->recv_overhead = 0;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_LATENCY) {
        perf_attr->latency = ucs_linear_func_make(iface->config.latency, 0.0);
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_MAX_INFLIGHT_EPS) {
        perf_attr->max_inflight_eps = SIZE_MAX;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_FLAGS) {
        perf_attr->flags = 0;
    }

    return UCS_OK;
}

static uct_iface_internal_ops_t uct_ze_ipc_iface_internal_ops = {
    .iface_query_v2         = uct_iface_base_query_v2,
    .iface_estimate_perf    = uct_ze_ipc_estimate_perf,
    .iface_vfs_refresh      = (uct_iface_vfs_refresh_func_t)
            ucs_empty_function,
    .iface_mem_element_pack = (uct_iface_mem_element_pack_func_t)
            ucs_empty_function_return_unsupported,
    .ep_query               = (uct_ep_query_func_t)
            ucs_empty_function_return_unsupported,
    .ep_invalidate          = (uct_ep_invalidate_func_t)
            ucs_empty_function_return_unsupported,
    .ep_connect_to_ep_v2    = (uct_ep_connect_to_ep_v2_func_t)
            ucs_empty_function_return_unsupported,
    .iface_is_reachable_v2  = uct_ze_ipc_iface_is_reachable_v2,
    .ep_is_connected        = uct_ze_ipc_ep_is_connected
};

/* Find the copy engine queue group ordinal for a device */
static ucs_status_t
uct_ze_ipc_find_copy_ordinal(ze_device_handle_t device, uint32_t *ordinal_p)
{
    uint32_t num_queue_groups = 0;
    ze_command_queue_group_properties_t *queue_props;
    ucs_status_t status;
    size_t size;
    uint32_t i;

    /* Query count first */
    status = UCT_ZE_FUNC_LOG_ERR(
            zeDeviceGetCommandQueueGroupProperties(device, &num_queue_groups,
                                                   NULL));
    if (status != UCS_OK) {
        return UCS_ERR_IO_ERROR;
    }

    if (num_queue_groups == 0) {
        ucs_error("no command queue groups found on ze device");
        return UCS_ERR_NO_DEVICE;
    }

    /* Allocate exact size needed */
    size        = num_queue_groups * sizeof(*queue_props);
    queue_props = ucs_alloc_on_stack(size, "queue_props");
    if (queue_props == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    for (i = 0; i < num_queue_groups; i++) {
        queue_props[i].stype = 
                ZE_STRUCTURE_TYPE_COMMAND_QUEUE_GROUP_PROPERTIES;
        queue_props[i].pNext = NULL;
        queue_props[i].flags = ZE_COMMAND_QUEUE_GROUP_PROPERTY_FLAG_COMPUTE |
                               ZE_COMMAND_QUEUE_GROUP_PROPERTY_FLAG_COPY;
    }

    /* Get command queue group properties of the device */
    status = UCT_ZE_FUNC_LOG_ERR(
            zeDeviceGetCommandQueueGroupProperties(device, &num_queue_groups,
                                                   queue_props));
    if (status != UCS_OK) {
        status = UCS_ERR_IO_ERROR;
        goto out_free;
    }

    /* Find dedicated copy engine (COPY but not COMPUTE) */
    for (i = 0; i < num_queue_groups; i++) {
        if ((queue_props[i].flags &
             ZE_COMMAND_QUEUE_GROUP_PROPERTY_FLAG_COPY) &&
            !(queue_props[i].flags &
              ZE_COMMAND_QUEUE_GROUP_PROPERTY_FLAG_COMPUTE)) {
            *ordinal_p = i;
            status     = UCS_OK;
            goto out_free;
        }
    }

    /* Fallback: any copy-capable queue */
    for (i = 0; i < num_queue_groups; i++) {
        if (queue_props[i].flags & 
            ZE_COMMAND_QUEUE_GROUP_PROPERTY_FLAG_COPY) {
            *ordinal_p = i;
            status     = UCS_OK;
            goto out_free;
        }
    }

    ucs_error("no copy-capable command queue found on ze device");
    status = UCS_ERR_NO_DEVICE;

out_free:
    ucs_free_on_stack(queue_props, size);
    return status;
}

static UCS_CLASS_INIT_FUNC(uct_ze_ipc_iface_t, uct_md_h uct_md,
                           uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    ze_command_queue_desc_t queue_desc = {};
    ze_event_pool_desc_t pool_desc     = {};
    ze_event_desc_t event_desc         = {};
    uint32_t copy_ordinal              = 0;
    uct_ze_ipc_iface_config_t *config;
    ucs_status_t status;
    unsigned i, j;

    config = ucs_derived_of(tl_config, uct_ze_ipc_iface_config_t);

    UCS_CLASS_CALL_SUPER_INIT(uct_base_iface_t, &uct_ze_ipc_iface_ops,
                              &uct_ze_ipc_iface_internal_ops, uct_md, worker,
                              params,
                              tl_config UCS_STATS_ARG(params->stats_root)
                                      UCS_STATS_ARG(UCT_ZE_IPC_TL_NAME));

    self->ze_context        = uct_ze_ipc_md_get_context(uct_md);
    self->ze_device         = uct_ze_ipc_md_get_device(uct_md);
    self->config            = *config;
    self->eventfd           = UCS_ASYNC_EVENTFD_INVALID_FD;
    self->pidfd_cache       = NULL;
    self->next_cmd_list     = 0;
    self->next_progress_idx = 0;

    /* clamp num_cmd_lists to max */
    self->num_cmd_lists = ucs_min(config->max_cmd_lists,
                                  UCT_ZE_IPC_MAX_CMD_LISTS);
    if (self->num_cmd_lists == 0) {
        self->num_cmd_lists = 1;
    }

    status = uct_ze_ipc_find_copy_ordinal(self->ze_device, &copy_ordinal);
    if (status != UCS_OK) {
        return status;
    }

    /* Initialize pidfd cache BEFORE creating command lists */
    self->pidfd_cache = kh_init(ze_ipc_pidfd_cache);
    if (self->pidfd_cache == NULL) {
        ucs_error("Failed to initialize pidfd cache");
        return UCS_ERR_NO_MEMORY;
    }

    /* Create immediate command lists */
    queue_desc.stype    = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC;
    queue_desc.ordinal  = copy_ordinal;
    queue_desc.mode     = ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS;
    queue_desc.index    = 0; /* must be 0 for immediate command lists */
    queue_desc.flags    = 0;
    queue_desc.priority = ZE_COMMAND_QUEUE_PRIORITY_NORMAL;

    pool_desc.stype     = ZE_STRUCTURE_TYPE_EVENT_POOL_DESC;
    pool_desc.count     = UCT_ZE_IPC_EVENTS_PER_CMDLIST;
    pool_desc.flags     = ZE_EVENT_POOL_FLAG_HOST_VISIBLE;

    event_desc.stype    = ZE_STRUCTURE_TYPE_EVENT_DESC;
    event_desc.signal   = ZE_EVENT_SCOPE_FLAG_HOST;
    event_desc.wait     = ZE_EVENT_SCOPE_FLAG_HOST;

    for (i = 0; i < self->num_cmd_lists; i++) {
        self->queue_desc[i].cmd_list        = NULL;
        self->queue_desc[i].event_pool      = NULL;
        self->queue_desc[i].event_put_idx   = 0;
        self->queue_desc[i].event_get_idx   = 0;
        for (j = 0; j < UCT_ZE_IPC_EVENTS_PER_CMDLIST; j++) {
            self->queue_desc[i].events[j] = NULL;
        }

        status = UCT_ZE_FUNC_LOG_ERR(
                zeCommandListCreateImmediate(self->ze_context, self->ze_device,
                                             &queue_desc,
                                             &self->queue_desc[i].cmd_list));
        if (status != UCS_OK) {
            status = UCS_ERR_IO_ERROR;
            goto err_destroy_lists;
        }

        status = UCT_ZE_FUNC_LOG_ERR(
                zeEventPoolCreate(self->ze_context, &pool_desc, 1,
                                  &self->ze_device,
                                  &self->queue_desc[i].event_pool));
        if (status != UCS_OK) {
            status = UCS_ERR_IO_ERROR;
            zeCommandListDestroy(self->queue_desc[i].cmd_list);
            self->queue_desc[i].cmd_list = NULL;
            goto err_destroy_lists;
        }

        for (j = 0; j < UCT_ZE_IPC_EVENTS_PER_CMDLIST; j++) {
            event_desc.index = j;
            status = UCT_ZE_FUNC_LOG_ERR(
                    zeEventCreate(self->queue_desc[i].event_pool, &event_desc,
                                  &self->queue_desc[i].events[j]));
            if (status != UCS_OK) {
                status = UCS_ERR_IO_ERROR;
                while (j-- > 0) {
                    zeEventDestroy(self->queue_desc[i].events[j]);
                }
                zeEventPoolDestroy(self->queue_desc[i].event_pool);
                self->queue_desc[i].event_pool = NULL;
                zeCommandListDestroy(self->queue_desc[i].cmd_list);
                self->queue_desc[i].cmd_list = NULL;
                goto err_destroy_lists;
            }
        }

        /* Initialize event queue for this command list */
        ucs_queue_head_init(&self->queue_desc[i].event_queue);
        ucs_queue_head_init(&self->queue_desc[i].free_event_descs);
        for (j = 0; j < UCT_ZE_IPC_EVENTS_PER_CMDLIST; j++) {
            self->queue_desc[i].event_descs[j].queue.next = NULL;
            ucs_queue_push(&self->queue_desc[i].free_event_descs,
                           &self->queue_desc[i].event_descs[j].queue);
        }
        ucs_recursive_spinlock_init(&self->queue_desc[i].lock, 0);
    }

    return UCS_OK;

err_destroy_lists:
    while (i-- > 0) {
        for (j = 0; j < UCT_ZE_IPC_EVENTS_PER_CMDLIST; j++) {
            if (self->queue_desc[i].events[j] != NULL) {
                zeEventDestroy(self->queue_desc[i].events[j]);
            }
        }

        if (self->queue_desc[i].event_pool != NULL) {
            zeEventPoolDestroy(self->queue_desc[i].event_pool);
        }

        if (self->queue_desc[i].cmd_list != NULL) {
            zeCommandListDestroy(self->queue_desc[i].cmd_list);
        }

        ucs_recursive_spinlock_destroy(&self->queue_desc[i].lock);
    }

    if (self->pidfd_cache != NULL) {
        kh_destroy(ze_ipc_pidfd_cache, self->pidfd_cache);
        self->pidfd_cache = NULL;
    }

    return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ze_ipc_iface_t)
{
    uct_ze_ipc_event_desc_t *event_desc;
    ucs_queue_elem_t *queue_elem;
    khiter_t khiter;
    pid_t pid;
    unsigned i, j;
    int pidfd;

    /* wait for and cleanup all pending operations */
    for (i = 0; i < self->num_cmd_lists; i++) {
        ucs_recursive_spin_lock(&self->queue_desc[i].lock);

        /* wait for events to complete before destroying command list */
        while ((queue_elem = ucs_queue_pull(
                        &self->queue_desc[i].event_queue)) != NULL) {
            event_desc = ucs_container_of(queue_elem, uct_ze_ipc_event_desc_t,
                                          queue);
            /* wait for event */
            zeEventHostSynchronize(event_desc->event, UINT64_MAX);

            /* unmap and cleanup */
            if (event_desc->mapped_addr != NULL) {
                uct_ze_ipc_unmap_memhandle(event_desc->pid, event_desc->address,
                                           event_desc->mapped_addr,
                                           self->ze_context, event_desc->dup_fd,
                                           self->config.enable_cache);
            }

            if (event_desc->comp != NULL) {
                uct_invoke_completion(event_desc->comp, UCS_OK);
            }

            UCT_ZE_FUNC_LOG_DEBUG(zeEventHostReset(event_desc->event));
        }

        ucs_recursive_spin_unlock(&self->queue_desc[i].lock);

        for (j = 0; j < UCT_ZE_IPC_EVENTS_PER_CMDLIST; j++) {
            if (self->queue_desc[i].events[j] != NULL) {
                zeEventDestroy(self->queue_desc[i].events[j]);
            }
        }

        if (self->queue_desc[i].event_pool != NULL) {
            zeEventPoolDestroy(self->queue_desc[i].event_pool);
        }

        /* Now safe to destroy command list */
        if (self->queue_desc[i].cmd_list != NULL) {
            zeCommandListDestroy(self->queue_desc[i].cmd_list);
        }

        ucs_recursive_spinlock_destroy(&self->queue_desc[i].lock);
    }

    if (self->eventfd != UCS_ASYNC_EVENTFD_INVALID_FD) {
        close(self->eventfd);
    }

    /* cleanup pidfd cache (after all unmap operations complete) */
    if (self->pidfd_cache != NULL) {
        for (khiter = kh_begin(self->pidfd_cache);
             khiter != kh_end(self->pidfd_cache); ++khiter) {
            if (kh_exist(self->pidfd_cache, khiter)) {
                pidfd = kh_value(self->pidfd_cache, khiter);
                pid   = kh_key(self->pidfd_cache, khiter);
                close(pidfd);
                ucs_debug("Closed cached pidfd=%d for pid %d", pidfd, pid);
            }
        }
        kh_destroy(ze_ipc_pidfd_cache, self->pidfd_cache);
        self->pidfd_cache = NULL;
    }
}

UCS_CLASS_DEFINE(uct_ze_ipc_iface_t, uct_base_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_ze_ipc_iface_t, uct_iface_t, uct_md_h,
                          uct_worker_h, const uct_iface_params_t*,
                          const uct_iface_config_t*);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_ze_ipc_iface_t, uct_iface_t);

static ucs_status_t
uct_ze_ipc_query_devices(uct_md_h uct_md,
                         uct_tl_device_resource_t **tl_devices_p,
                         unsigned *num_tl_devices_p)
{
    return uct_ze_base_query_devices(uct_md, tl_devices_p, num_tl_devices_p);
}

UCT_TL_DEFINE(&uct_ze_ipc_component, ze_ipc, uct_ze_ipc_query_devices,
              uct_ze_ipc_iface_t, "ZE_IPC_", uct_ze_ipc_iface_config_table,
              uct_ze_ipc_iface_config_t);
