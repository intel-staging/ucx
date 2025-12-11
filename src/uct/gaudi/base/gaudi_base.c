/*
 * Copyright (C) Intel Corporation, 2025. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gaudi_base.h"
#include <uct/gaudi/gaudi_gdr/gaudi_gdr_md.h>
#include <ucs/sys/module.h>
#include <ucs/memory/numa.h>
#include <ucs/sys/sys.h>
#include <ucs/sys/string.h>
#include <ucs/sys/topo/base/topo.h>
#include <ucs/arch/atomic.h>
#include <pthread.h>

#include <inttypes.h>
#include <fcntl.h>
#include <hlthunk.h>
#include <synapse_api.h>

#define UCT_GAUDI_MAX_DEVICES 8

int uct_gaudi_base_get_fd(int device_id, bool *fd_created)
{
    synDeviceInfo deviceInfo;

    if (synDeviceGetInfo(-1, &deviceInfo) != synSuccess) {
        int fd = hlthunk_open_by_module_id(device_id);
        if (fd < 0) {
            ucs_info("failed to get device fd via hlthunk_open_by_module_id, "
                     "id %d",
                     device_id);
            fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, NULL);
        }

        if (fd >= 0 && fd_created != NULL) {
            *fd_created = true;
        }
        return fd;
    }

    if (fd_created != NULL) {
        *fd_created = false;
    }
    return deviceInfo.fd;
}

void uct_gaudi_base_close_fd(int fd, bool fd_created)
{
    if (fd_created && fd >= 0) {
        hlthunk_close(fd);
    }
}

void uct_gaudi_base_close_dmabuf_fd(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

ucs_status_t uct_gaudi_base_get_sysdev(int fd, ucs_sys_device_t *sys_dev)
{
    ucs_status_t status;
    char pci_bus_id[13];
    int rc;

    rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
    if (rc != 0) {
        ucs_error("failed to get pci_bus_id via hlthunk_get_pci_bus_id_from_fd "
                  "(fd=%d)",
                  fd);
        return UCS_ERR_IO_ERROR;
    }

    status = ucs_topo_find_device_by_bdf_name(pci_bus_id, sys_dev);
    if (status != UCS_OK) {
        ucs_error("failed to get sys device from pci_bus_id %s", pci_bus_id);
        return status;
    }

    return UCS_OK;
}

ucs_status_t uct_gaudi_base_get_info(int fd,
                                     uint64_t *device_base_allocated_address,
                                     uint64_t *device_base_address,
                                     uint64_t *totalSize, int *dmabuf_fd)
{
    uint64_t addr, hbm_pool_start, size, offset;
    scal_handle_t scal_handle;
    scal_pool_handle_t scal_pool_handle;
    scal_memory_pool_infoV2 scal_mem_pool_info;
    int rc;

    rc = scal_get_handle_from_fd(fd, &scal_handle);
    if (rc != UCT_GAUID_SCAL_SUCCESS) {
        /*
         * If rc value equal UCT_GAUID_SCAL_SUCCESS, it mean that it use synDeviceAcquireByModuleId to open Gaudi device.
         * Otherwise, the device is opened via hlthunk_open_by_module_id function.
         */
        rc = scal_init(fd, "", &scal_handle, NULL);
    }

    if (rc != UCT_GAUID_SCAL_SUCCESS) {
        ucs_error("failed to get scal handle from gaudi device (fd=%d, rc=%d)",
                  fd, rc);
        return UCS_ERR_IO_ERROR;
    }

    rc = scal_get_pool_handle_by_name(scal_handle, "global_hbm",
                                      &scal_pool_handle);
    if (rc != UCT_GAUID_SCAL_SUCCESS) {
        ucs_error("failed to get scal pool");
        return UCS_ERR_INVALID_ADDR;
    }

    rc = scal_pool_get_infoV2(scal_pool_handle, &scal_mem_pool_info);
    if (rc != UCT_GAUID_SCAL_SUCCESS) {
        ucs_error("failed to get scal pool info");
        return UCS_ERR_INVALID_ADDR;
    }

    addr           = scal_mem_pool_info.device_base_allocated_address;
    hbm_pool_start = scal_mem_pool_info.device_base_address;
    size           = scal_mem_pool_info.totalSize;
    offset         = hbm_pool_start - addr;
    *dmabuf_fd     = hlthunk_device_mapped_memory_export_dmabuf_fd(
            fd, addr, size, offset, (O_RDWR | O_CLOEXEC));
    if (*dmabuf_fd < 0) {
        ucs_error("failed to get dmabuf fd from fd %d", fd);
        return UCS_ERR_INVALID_ADDR;
    }

    *device_base_allocated_address = addr;
    *device_base_address           = hbm_pool_start;
    *totalSize                     = size;
    return UCS_OK;
}

ucs_status_t
uct_gaudi_base_query_devices(uct_md_h md,
                             uct_tl_device_resource_t **tl_devices_p,
                             unsigned *num_tl_devices_p)
{
    uct_gaudi_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_md_t);
    ucs_sys_device_t sys_dev;
    ucs_status_t status;

    status = uct_gaudi_base_get_sysdev(gaudi_md->fd, &sys_dev);
    if (status != UCS_OK) {
        return status;
    }
    return uct_single_device_resource(md, md->component->name,
                                      UCT_DEVICE_TYPE_ACC, sys_dev,
                                      tl_devices_p, num_tl_devices_p);
}

void uct_gaudi_base_get_sys_dev_by_module(int module_id,
                                          ucs_sys_device_t *sys_dev_p)
{
    char sysfs_path[256];
    char bus_id_buffer[64];
    FILE *fp;
    ucs_status_t status;
    int accel_id;
    int found_module_id;

    /* Use sysfs to find the module */
    for (accel_id = 0; accel_id < UCT_GAUDI_MAX_DEVICES; accel_id++) {
        /* Check if this accel device corresponds to our target module_id */
        snprintf(sysfs_path, sizeof(sysfs_path),
                 "/sys/class/accel/accel%d/device/module_id", accel_id);

        fp = fopen(sysfs_path, "r");
        if (fp == NULL) {
            continue; /* This accel device doesn't exist or no permissions */
        }

        if (fscanf(fp, "%d", &found_module_id) != 1 ||
            found_module_id != module_id) {
            fclose(fp);
            continue;
        }
        fclose(fp);

        /* Found our target module! Get its PCI bus ID directly */
        snprintf(sysfs_path, sizeof(sysfs_path),
                 "/sys/class/accel/accel%d/device/pci_addr", accel_id);

        fp = fopen(sysfs_path, "r");
        if (fp == NULL) {
            /* Found module but couldn't open pci_addr */
            break;
        }

        if (fscanf(fp, "%63s", bus_id_buffer) != 1) {
            fclose(fp);
            break;
        }
        fclose(fp);

        /* Use ucs_topo_find_device_by_bdf_name which handles BDF parsing */
        status = ucs_topo_find_device_by_bdf_name(bus_id_buffer, sys_dev_p);
        if (status != UCS_OK) {
            ucs_debug("failed to find system device for module %d (PCI: %s): %s",
                      module_id, bus_id_buffer, ucs_status_string(status));
            *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
            return;
        }

        ucs_debug("successfully mapped Gaudi module %d (accel%d) to "
                  "system device (PCI: %s)",
                  module_id, accel_id, bus_id_buffer);
        return;
    }

    /* Module not found */
    *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
}

/* Device discovery - enumerate all Gaudi devices and register with topology */
ucs_status_t uct_gaudi_base_discover_devices(void)
{
    static pthread_mutex_t discovery_mutex  = PTHREAD_MUTEX_INITIALIZER;
    static volatile uint32_t devices_discovered = 0;
    ucs_status_t status                     = UCS_OK;
    ucs_sys_device_t sys_dev;
    char device_name[16];
    int registered_devices = 0;
    int i;

    /* Check if already discovered - use atomic load for memory ordering */
    if (ucs_atomic_fadd32(&devices_discovered, 0)) {
        return UCS_OK;
    }

    pthread_mutex_lock(&discovery_mutex);

    /* Double-check after acquiring lock */
    if (ucs_atomic_fadd32(&devices_discovered, 0)) {
        goto out;
    }

    ucs_debug("starting Gaudi device discovery");

    /* Enumerate devices by trying all possible module IDs */
    for (i = 0; i < UCT_GAUDI_MAX_DEVICES; ++i) {
        uct_gaudi_base_get_sys_dev_by_module(i, &sys_dev);
        if (sys_dev != UCS_SYS_DEVICE_ID_UNKNOWN) {
            /* Register with topology system using sequential naming */
            ucs_snprintf_safe(device_name, sizeof(device_name), "GAUDI_%d",
                              registered_devices);
            status = ucs_topo_sys_device_set_name(sys_dev, device_name, 100);
            if (status != UCS_OK) {
                ucs_warn("failed to set name for Gaudi device module %d", i);
                continue;
            }

            /* Store module ID in system device for later retrieval */
            status = ucs_topo_sys_device_set_user_value(sys_dev, i);
            if (status != UCS_OK) {
                ucs_warn("failed to set user value for Gaudi device module %d",
                         i);
                continue;
            }

            registered_devices++;
            ucs_debug("successfully registered module %d as %s (sys_dev %d)", i,
                      device_name, sys_dev);
        } else {
            ucs_debug("module %d not available", i);
        }
    }

    if (registered_devices > 0) {
        ucs_debug("discovered %d Gaudi devices", registered_devices);
        /* Use atomic store to ensure visibility to other threads */
        ucs_atomic_add32(&devices_discovered, 1);
        status = UCS_OK;
    } else {
        ucs_debug("no Gaudi devices found");
        status = UCS_ERR_NO_DEVICE;
    }

out:
    pthread_mutex_unlock(&discovery_mutex);
    return status;
}

UCS_MODULE_INIT()
{
    return UCS_OK;
}
