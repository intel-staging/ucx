/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef UCT_ZE_IPC_IFACE_H
#define UCT_ZE_IPC_IFACE_H

#include "ze_ipc_md.h"

#include <uct/base/uct_iface.h>
#include <ucs/datastruct/khash.h>

#include <level_zero/ze_api.h>


typedef struct uct_ze_ipc_iface_config {
    uct_iface_config_t super;         /**< Base UCX interface configuration */
    unsigned           max_poll;      /**< Maximum poll attempts without progress */
    unsigned           max_cmd_lists; /**< Maximum number of command lists for parallel progress */
    int                enable_cache;  /**< Enable or disable IPC handle cache */
    double             bandwidth;     /**< Estimated bandwidth */
    double             latency;       /**< Estimated latency */
    double             overhead;      /**< Estimated CPU overhead */
} uct_ze_ipc_iface_config_t;


/* Queue descriptor for each command list */
typedef struct uct_ze_ipc_queue_desc {
    ucs_queue_elem_t         queue;       /**< Entry in the active queue list */
    ze_command_list_handle_t cmd_list;    /**< Immediate command list */
    ucs_queue_head_t         event_queue; /**< Queue of outstanding events */
} uct_ze_ipc_queue_desc_t;


/* Event descriptor for async tracking */
typedef struct uct_ze_ipc_event_desc {
    ze_event_handle_t      event;        /**< Level Zero event handle */
    ze_event_pool_handle_t event_pool;   /**< Event pool the event belongs to */
    void                   *mapped_addr; /**< Mapped remote memory address */
    uct_completion_t       *comp;        /**< UCX completion object */
    ucs_queue_elem_t       queue;        /**< Element in associated event queue */
    int                    dup_fd;       /**< Duplicated FD for remote handle (or -1) */
    pid_t                  pid;          /**< Remote process ID for cache lookup */
    uintptr_t              address;      /**< Base address for cache lookup */
} uct_ze_ipc_event_desc_t;


/* Add hash type declaration before iface struct */
KHASH_INIT(ze_ipc_pidfd_cache, pid_t, int, 1, kh_int_hash_func,
           kh_int_hash_equal);


typedef struct uct_ze_ipc_iface {
    uct_base_iface_t            super;         /**< Base UCX interface */
    ze_context_handle_t         ze_context;    /**< Level Zero execution context */
    ze_device_handle_t          ze_device;     /**< Level Zero device */
    uct_ze_ipc_iface_config_t   config;        /**< Interface configuration */
    int                         eventfd;       /**< eventfd for async progress */
    uct_ze_ipc_queue_desc_t     queue_desc
            [UCT_ZE_IPC_MAX_CMD_LISTS];        /**< Array of command list descriptors */
    ucs_queue_head_t            active_queue;  /**< Queue of active command lists */
    unsigned                    num_cmd_lists; /**< Number of created command lists */
    khash_t(ze_ipc_pidfd_cache) *pidfd_cache;  /**< Pidfd cache */
} uct_ze_ipc_iface_t;


#endif
