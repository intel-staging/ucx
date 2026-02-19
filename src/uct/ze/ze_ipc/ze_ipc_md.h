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


/**
 * @brief Level Zero (ZE) IPC remote key for put/get
 */
typedef struct uct_ze_ipc_rkey {
    ze_ipc_mem_handle_t ph;      /**< IPC memory handle */
    pid_t               pid;     /**< Process ID */
    uintptr_t           d_bptr;  /**< Allocation base address */
    size_t              b_len;   /**< Allocation size */
    int                 dev_num; /**< Device number */
} uct_ze_ipc_rkey_t;


/**
 * @brief Level Zero (ZE) IPC unpacked remote key
 */
typedef struct uct_ze_ipc_unpacked_rkey {
    uct_ze_ipc_rkey_t super;       /**< Base remote key */
    int               cmd_list_id; /**< Command list ID */
} uct_ze_ipc_unpacked_rkey_t;


#endif
