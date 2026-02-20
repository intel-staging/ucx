/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef UCT_ZE_IPC_CACHE_H_
#define UCT_ZE_IPC_CACHE_H_

#include "ze_ipc_md.h"

#include <level_zero/ze_api.h>


typedef struct uct_ze_ipc_iface uct_ze_ipc_iface_t;


/**
 * @brief Map IPC handle (with caching)
 *
 * @param iface        ZE IPC interface
 * @param key          Pointer to the ze IPC remote memory key containing
 *                     handle and other metadata needed for mapping
 * @param ze_context   Level Zero context
 * @param ze_device    Level Zero device
 * @param mapped_addr  Pointer to store the resulting mapped local address
 * @param dup_fd       Pointer to store the returned duplicated FD
 *
 * @return UCS_OK on success or error status on failure
 */
ucs_status_t uct_ze_ipc_map_memhandle(uct_ze_ipc_iface_t *iface,
                                      const uct_ze_ipc_rkey_t *key,
                                      ze_context_handle_t ze_context,
                                      ze_device_handle_t ze_device,
                                      void **mapped_addr, int *dup_fd);


/**
 * @brief Unmap IPC handle (with reference counting)
 *
 * @param pid           Remote PID
 * @param address       Remote base address
 * @param mapped_addr   Local mapped address
 * @param ze_context    Level Zero context
 * @param dup_fd        Duplicated FD
 * @param cache_enabled Whether caching is enabled
 *
 * @return UCS_OK on success or error status on failure
 */
ucs_status_t uct_ze_ipc_unmap_memhandle(pid_t pid, uintptr_t address,
                                        void *mapped_addr,
                                        ze_context_handle_t ze_context,
                                        int dup_fd, int cache_enabled);


#endif
