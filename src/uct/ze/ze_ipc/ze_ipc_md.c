/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ze_ipc_md.h"

#include <uct/ze/base/ze_base.h>
#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>
#include <ucs/type/class.h>

#include <string.h>


#define UCT_ZE_IPC_MD_MAX_ROOT_DEVICES 32
#define UCT_ZE_IPC_MD_MAX_SUBDEVICES   8


static ze_device_handle_t
uct_ze_ipc_get_device_handle_by_global_id(ze_driver_handle_t ze_driver,
                                           int global_id)
{
    ze_device_handle_t root_devices[UCT_ZE_IPC_MD_MAX_ROOT_DEVICES];
    ze_device_handle_t subdevices[UCT_ZE_IPC_MD_MAX_SUBDEVICES];
    uint32_t root_dev_count;
    uint32_t subdev_count;
    ze_device_handle_t root_device;
    int global_idx = 0;
    ze_result_t ret;
    int i, j;

    if (global_id < 0) {
        return NULL;
    }

    root_dev_count = UCT_ZE_IPC_MD_MAX_ROOT_DEVICES;
    ret = zeDeviceGet(ze_driver, &root_dev_count, root_devices);
    if (ret != ZE_RESULT_SUCCESS) {
        return NULL;
    }

    for (i = 0; i < (int)root_dev_count; i++) {
        root_device  = root_devices[i];
        subdev_count = 0;
        ret          = zeDeviceGetSubDevices(root_device, &subdev_count, NULL);

        if ((ret == ZE_RESULT_SUCCESS) && (subdev_count > 0)) {
            if (subdev_count > UCT_ZE_IPC_MD_MAX_SUBDEVICES) {
                subdev_count = UCT_ZE_IPC_MD_MAX_SUBDEVICES;
            }

            ret = zeDeviceGetSubDevices(root_device, &subdev_count,
                                        subdevices);
            if (ret != ZE_RESULT_SUCCESS) {
                continue;
            }

            for (j = 0; j < (int)subdev_count; j++) {
                if (global_idx == global_id) {
                    return subdevices[j];
                }

                global_idx++;
            }
        } else {
            if (global_idx == global_id) {
                return root_device;
            }

            global_idx++;
        }
    }

    return NULL;
}

static int
uct_ze_ipc_get_subdevice_global_id_by_device_handle(ze_driver_handle_t ze_driver,
                                                     ze_device_handle_t device)
{
    ze_device_handle_t root_devices[UCT_ZE_IPC_MD_MAX_ROOT_DEVICES];
    ze_device_handle_t subdevices[UCT_ZE_IPC_MD_MAX_SUBDEVICES];
    uint32_t root_dev_count;
    uint32_t subdev_count;
    ze_device_handle_t root_device;
    int global_idx = 0;
    ze_result_t ret;
    int i, j;

    if (device == NULL) {
        return -1;
    }

    root_dev_count = UCT_ZE_IPC_MD_MAX_ROOT_DEVICES;
    ret = zeDeviceGet(ze_driver, &root_dev_count, root_devices);
    if (ret != ZE_RESULT_SUCCESS) {
        return -1;
    }

    for (i = 0; i < (int)root_dev_count; i++) {
        root_device  = root_devices[i];
        subdev_count = 0;
        ret          = zeDeviceGetSubDevices(root_device, &subdev_count, NULL);

        if ((ret == ZE_RESULT_SUCCESS) && (subdev_count > 0)) {
            if (subdev_count > UCT_ZE_IPC_MD_MAX_SUBDEVICES) {
                subdev_count = UCT_ZE_IPC_MD_MAX_SUBDEVICES;
            }

            ret = zeDeviceGetSubDevices(root_device, &subdev_count,
                                        subdevices);
            if (ret != ZE_RESULT_SUCCESS) {
                continue;
            }

            for (j = 0; j < (int)subdev_count; j++) {
                if (subdevices[j] == device) {
                    return global_idx;
                }

                global_idx++;
            }
        } else {
            if (root_device == device) {
                return global_idx;
            }

            global_idx++;
        }
    }

    return -1;
}


/* Level Zero (ZE) IPC MD descriptor */
typedef struct uct_ze_ipc_md {
    uct_md_t            super;      /* Domain info */
    ze_context_handle_t ze_context; /* Level Zero context handle */
    ze_device_handle_t  ze_device;  /* Level Zero device handle */
} uct_ze_ipc_md_t;


/* Level Zero (ZE) IPC domain configuration */
typedef struct uct_ze_ipc_md_config {
    uct_md_config_t super;          /* Base MD configuration */
    int             device_ordinal; /* Level Zero device index (ordinal) */
} uct_ze_ipc_md_config_t;


/* Level Zero (ZE) IPC region registered for exposure */
typedef struct uct_ze_ipc_lkey {
    ze_ipc_mem_handle_t ph;      /* IPC memory handle */
    pid_t               pid;     /* Process ID */
    uintptr_t           d_bptr;  /* Allocation base address */
    size_t              b_len;   /* Allocation size */
    int                 dev_num; /* Device number */
} uct_ze_ipc_lkey_t;


static ucs_config_field_t uct_ze_ipc_md_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_ze_ipc_md_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

    {"DEVICE_ORDINAL", "0", "Global subdevice ordinal for IPC operations.",
     ucs_offsetof(uct_ze_ipc_md_config_t, device_ordinal), UCS_CONFIG_TYPE_INT},

    {NULL}
};

static ucs_status_t
uct_ze_ipc_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr)
{
    uct_md_base_md_query(md_attr);

    md_attr->rkey_packed_size = sizeof(uct_ze_ipc_rkey_t);
    md_attr->flags            = UCT_MD_FLAG_REG | UCT_MD_FLAG_NEED_RKEY;
    md_attr->reg_mem_types    = UCS_BIT(UCS_MEMORY_TYPE_ZE_DEVICE);
    md_attr->cache_mem_types  = UCS_BIT(UCS_MEMORY_TYPE_ZE_DEVICE);
    md_attr->access_mem_types = UCS_BIT(UCS_MEMORY_TYPE_ZE_DEVICE);

    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_mkey_pack(uct_md_h uct_md, uct_mem_h memh, void *address,
                     size_t length, const uct_md_mkey_pack_params_t *params,
                     void *mkey_buffer)
{
    uct_ze_ipc_lkey_t *lkey = memh;
    uct_ze_ipc_rkey_t *rkey = mkey_buffer;

    rkey->ph      = lkey->ph;
    rkey->pid     = lkey->pid;
    rkey->d_bptr  = lkey->d_bptr;
    rkey->b_len   = lkey->b_len;
    rkey->dev_num = lkey->dev_num;

    return UCS_OK;
}

static ucs_status_t uct_ze_ipc_pack_lkey(uct_ze_ipc_md_t *md, void *address,
                                         size_t length, uct_ze_ipc_lkey_t *lkey)
{
    ze_device_handle_t alloc_device         = NULL;
    ze_memory_allocation_properties_t props = {
        .stype = ZE_STRUCTURE_TYPE_MEMORY_ALLOCATION_PROPERTIES
    };
    ucs_status_t status;
    ze_result_t ret;
    ze_driver_handle_t ze_driver;
    void *base_address;
    size_t alloc_size;
    int global_id;

    /* Get allocation properties to verify device memory and get device */
    ret = zeMemGetAllocProperties(md->ze_context, address, &props,
                                  &alloc_device);
    if ((ret != ZE_RESULT_SUCCESS) || (props.type != ZE_MEMORY_TYPE_DEVICE)) {
        ucs_error("zeMemGetAllocProperties(addr %p) failed or not ZE device "
                  "memory: ret 0x%x type %d",
                  address, ret, (int)props.type);
        return UCS_ERR_INVALID_ADDR;
    }

    /* Get base address and allocation size */
    status = UCT_ZE_FUNC_LOG_ERR(zeMemGetAddressRange(md->ze_context, address,
                                                      &base_address,
                                                      &alloc_size));
    if (status != UCS_OK) {
        ucs_error("failed to get address range for addr %p", address);
        return UCS_ERR_INVALID_ADDR;
    }

    /* Find which subdevice this memory belongs to */
    ze_driver = uct_ze_base_get_driver();
    if (ze_driver == NULL) {
        ucs_error("failed to get ze driver");
        return UCS_ERR_NO_DEVICE;
    }

    global_id = uct_ze_ipc_get_subdevice_global_id_by_device_handle(
            ze_driver, alloc_device);
    if (global_id < 0) {
        ucs_error("Could not find subdevice for allocation device %p",
                  (void*)alloc_device);
        return UCS_ERR_INVALID_ADDR;
    }

    /* Get IPC handle - MUST use same context as allocation */
    status = UCT_ZE_FUNC_LOG_ERR(
            zeMemGetIpcHandle(md->ze_context, base_address, &lkey->ph));
    if (status != UCS_OK) {
        ucs_error("failed to get IPC handle for addr %p", base_address);
        return UCS_ERR_IO_ERROR;
    }

    /* Local key owns the IPC handle reference */
    lkey->pid     = getpid();
    lkey->d_bptr  = (uintptr_t)base_address;
    lkey->b_len   = alloc_size;
    lkey->dev_num = global_id;

    ucs_trace("Packed local key: base addr 0x%lx len %zu dev %d pid %d",
              lkey->d_bptr, lkey->b_len, lkey->dev_num, lkey->pid);

    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_mem_reg(uct_md_h uct_md, void *address, size_t length,
                   const uct_md_mem_reg_params_t *params, uct_mem_h *memh_p)
{
    uct_ze_ipc_md_t *md = ucs_derived_of(uct_md, uct_ze_ipc_md_t);
    uct_ze_ipc_lkey_t *lkey;
    ucs_status_t status;

    lkey = ucs_malloc(sizeof(*lkey), "uct_ze_ipc_lkey_t");
    if (lkey == NULL) {
        ucs_error("failed to allocate ze ipc lkey");
        return UCS_ERR_NO_MEMORY;
    }

    status = uct_ze_ipc_pack_lkey(md, address, length, lkey);
    if (status != UCS_OK) {
        ucs_free(lkey);
        return status;
    }

    *memh_p = lkey;
    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_mem_dereg(uct_md_h uct_md, const uct_md_mem_dereg_params_t *params)
{
    uct_ze_ipc_md_t *md = ucs_derived_of(uct_md, uct_ze_ipc_md_t);
    uct_ze_ipc_lkey_t *lkey;

    UCT_MD_MEM_DEREG_CHECK_PARAMS(params, 0);

    lkey = params->memh;

    /* Release IPC handle reference - local key owns it */
    zeMemPutIpcHandle(md->ze_context, lkey->ph);

    ucs_free(lkey);
    return UCS_OK;
}

static ucs_status_t
uct_ze_ipc_rkey_unpack(uct_component_t *component, const void *rkey_buffer,
                       const uct_rkey_unpack_params_t *params,
                       uct_rkey_t *rkey_p, void **handle_p)
{
    const uct_ze_ipc_rkey_t *packed = rkey_buffer;
    uct_ze_ipc_unpacked_rkey_t *unpacked;

    unpacked = ucs_malloc(sizeof(*unpacked), "uct_ze_ipc_unpacked_rkey_t");
    if (unpacked == NULL) {
        ucs_error("failed to allocate ze ipc unpacked rkey");
        return UCS_ERR_NO_MEMORY;
    }

    /* Copy packed data - no ownership transfer */
    unpacked->super = *packed;

    /* Deterministic transport hash for endpoint-side queue selection */
    unpacked->path_hash = (uint32_t)(packed->d_bptr >> 16);

    *handle_p = NULL;
    *rkey_p   = (uintptr_t)unpacked;

    ucs_trace("unpacked rkey: dev %d addr 0x%lx path_hash 0x%x",
              unpacked->super.dev_num, unpacked->super.d_bptr,
              unpacked->path_hash);

    return UCS_OK;
}

static ucs_status_t uct_ze_ipc_rkey_release(uct_component_t *component,
                                            uct_rkey_t rkey, void *handle)
{
    ucs_assert(handle == NULL);
    /* unpacked_rkey does NOT own the IPC handle, just free the struct */
    ucs_free((void*)rkey);
    return UCS_OK;
}

static void uct_ze_ipc_md_close(uct_md_h uct_md)
{
    uct_ze_ipc_md_t *md = ucs_derived_of(uct_md, uct_ze_ipc_md_t);

    if (md->ze_context != NULL) {
        zeContextDestroy(md->ze_context);
    }

    ucs_free(md);
}

ze_context_handle_t uct_ze_ipc_md_get_context(uct_md_h uct_md)
{
    uct_ze_ipc_md_t *md = ucs_derived_of(uct_md, uct_ze_ipc_md_t);

    return md->ze_context;
}

ze_device_handle_t uct_ze_ipc_md_get_device(uct_md_h uct_md)
{
    uct_ze_ipc_md_t *md = ucs_derived_of(uct_md, uct_ze_ipc_md_t);

    return md->ze_device;
}

static ucs_status_t
uct_ze_ipc_md_open(uct_component_h component, const char *md_name,
                   const uct_md_config_t *uct_md_config, uct_md_h *uct_md)
{
    static uct_md_ops_t md_ops = {
        .close              = uct_ze_ipc_md_close,
        .query              = uct_ze_ipc_md_query,
        .mem_alloc          = (uct_md_mem_alloc_func_t)
                ucs_empty_function_return_unsupported,
        .mem_free           = (uct_md_mem_free_func_t)
                ucs_empty_function_return_unsupported,
        .mem_advise         = (uct_md_mem_advise_func_t)
                ucs_empty_function_return_unsupported,
        .mem_reg            = uct_ze_ipc_mem_reg,
        .mem_dereg          = uct_ze_ipc_mem_dereg,
        .mem_query          = (uct_md_mem_query_func_t)
                ucs_empty_function_return_unsupported,
        .mkey_pack          = uct_ze_ipc_mkey_pack,
        .mem_attach         = (uct_md_mem_attach_func_t)
                ucs_empty_function_return_unsupported,
        .detect_memory_type = (uct_md_detect_memory_type_func_t)
                ucs_empty_function_return_unsupported,
    };

    uct_ze_ipc_md_config_t *config = ucs_derived_of(uct_md_config,
                                                    uct_ze_ipc_md_config_t);
    ze_context_desc_t context_desc = {};
    uct_ze_ipc_md_t *md;
    ze_driver_handle_t ze_driver;
    ucs_status_t status;

    ze_driver = uct_ze_base_get_driver();
    if (ze_driver == NULL) {
        return UCS_ERR_NO_DEVICE;
    }

    md = ucs_malloc(sizeof(*md), "uct_ze_ipc_md_t");
    if (md == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    /* Get device handle by global sub-device ordinal */
    md->ze_device = uct_ze_ipc_get_device_handle_by_global_id(
            ze_driver, config->device_ordinal);
    if (md->ze_device == NULL) {
        ucs_error("failed to get ze device handle at ordinal %d",
                  config->device_ordinal);
        ucs_free(md);
        return UCS_ERR_NO_DEVICE;
    }

    status = UCT_ZE_FUNC_LOG_ERR(
            zeContextCreate(ze_driver, &context_desc, &md->ze_context));
    if (status != UCS_OK) {
        ucs_free(md);
        return UCS_ERR_NO_DEVICE;
    }

    md->super.ops       = &md_ops;
    md->super.component = &uct_ze_ipc_component;

    *uct_md = (uct_md_h)md;

    ucs_debug("opened ZE IPC MD: sub-device %d context %p",
              config->device_ordinal, (void*)md->ze_context);

    return UCS_OK;
}

uct_component_t uct_ze_ipc_component = {
    .query_md_resources = uct_ze_base_query_md_resources,
    .md_open            = uct_ze_ipc_md_open,
    .cm_open            = (uct_component_cm_open_func_t)
            ucs_empty_function_return_unsupported,
    .rkey_unpack        = uct_ze_ipc_rkey_unpack,
    .rkey_ptr           = (uct_component_rkey_ptr_func_t)
            ucs_empty_function_return_unsupported,
    .rkey_release       = uct_ze_ipc_rkey_release,
    .rkey_compare       = uct_base_rkey_compare,
    .name               = "ze_ipc",
    .md_config          =
            {
                .name   = "ZE-IPC memory domain",
                .prefix = "ZE_IPC_",
                .table  = uct_ze_ipc_md_config_table,
                .size   = sizeof(uct_ze_ipc_md_config_t),
            },
    .cm_config          = UCS_CONFIG_EMPTY_GLOBAL_LIST_ENTRY,
    .tl_list            = UCT_COMPONENT_TL_LIST_INITIALIZER(
            &uct_ze_ipc_component),
    .flags              = 0,
    .md_vfs_init        = (uct_component_md_vfs_init_func_t)ucs_empty_function
};
UCT_COMPONENT_REGISTER(&uct_ze_ipc_component);
