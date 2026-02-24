/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef UCT_ZE_IPC_MD_H
#define UCT_ZE_IPC_MD_H

#include <uct/base/uct_md.h>
#include <uct/ze/base/ze_base.h>
#include <ucs/config/types.h>

#include <level_zero/ze_api.h>


extern uct_component_t uct_ze_ipc_component;


/* Level Zero (ZE) IPC remote key for put/get */
typedef struct uct_ze_ipc_rkey {
    ze_ipc_mem_handle_t ph;      /**< IPC memory handle */
    pid_t               pid;     /**< Process ID */
    uintptr_t           d_bptr;  /**< Allocation base address */
    size_t              b_len;   /**< Allocation size */
    int                 dev_num; /**< Device number */
} uct_ze_ipc_rkey_t;


/* Level Zero (ZE) IPC unpacked remote key */
typedef struct uct_ze_ipc_unpacked_rkey {
    uct_ze_ipc_rkey_t super;     /**< Base remote key */
    uint32_t          path_hash; /**< Deterministic transport path hash */
} uct_ze_ipc_unpacked_rkey_t;


ze_context_handle_t uct_ze_ipc_md_get_context(uct_md_h uct_md);

ze_device_handle_t uct_ze_ipc_md_get_device(uct_md_h uct_md);


#endif
