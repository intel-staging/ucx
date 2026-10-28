/**
 * Copyright (C) Intel Corporation, 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "test_ze_copy_import.h"
#include <common/test.h>

extern "C" {
#include <uct/api/uct.h>
#include <uct/ze/base/ze_base.h>
#include <ucs/config/global_opts.h>
#include <ucs/memory/memtype_cache.h>
}


/*
 * Smoke tests for the ze_copy MD: lifecycle, capability query, allocation
 * and memory-type detection. The ze_copy MD is the path used by UCP for
 * VRAM<->host staging on Intel XPU.
 */
class test_ze_copy_md : public ucs::test {
protected:
    void SetUp() override
    {
        ucs::test::SetUp();
        if (uct_ze_base_init() != ZE_RESULT_SUCCESS) {
            UCS_TEST_SKIP_R("Level Zero runtime not available");
        }
        if (uct_ze_base_get_num_devices() == 0) {
            UCS_TEST_SKIP_R("No Level Zero devices available");
        }
    }

    /* Open the first ze_copy MD into an owning handle, so that it is closed
     * on every exit path; skip the test if no MD can be opened. */
    static void open_md_or_skip(ucs::handle<uct_md_h> &md,
                                const char *host_import = NULL)
    {
        uct_md_resource_desc_t *resources = NULL;
        unsigned num                      = 0;
        uct_md_config_t *md_config        = NULL;
        uct_md_h md_h                     = NULL;
        ucs_status_t status;

        status = uct_ze_copy_component.query_md_resources(
                &uct_ze_copy_component, &resources, &num);
        EXPECT_UCS_OK(status);
        if (num == 0) {
            ucs_free(resources);
            UCS_TEST_SKIP_R("No ze_cpy MD resources on this system");
        }

        status = uct_md_config_read(&uct_ze_copy_component, NULL, NULL,
                                    &md_config);
        if (status != UCS_OK) {
            ucs_free(resources);
            UCS_TEST_ABORT(
                    "uct_md_config_read failed: " << ucs_status_string(status));
        }

        if (host_import != NULL) {
            EXPECT_UCS_OK(uct_config_modify(md_config, "ZE_COPY_HOST_IMPORT",
                                            host_import));
        }

        status = uct_md_open(&uct_ze_copy_component, resources[0].md_name,
                             md_config, &md_h);
        uct_config_release(md_config);
        ucs_free(resources);
        if (status != UCS_OK) {
            UCS_TEST_SKIP_R("Could not open ze_cpy MD on this system");
        }

        md.reset(md_h, uct_md_close);
    }

    /* Allocate ZE_DEVICE memory through the MD; skip the test if the MD
     * cannot allocate it on this system. The caller owns the MD. */
    static void alloc_device_or_skip(uct_md_h md, size_t *length_p,
                                     void **addr_p, uct_mem_h *memh_p)
    {
        ucs_status_t status = md->ops->mem_alloc(md, length_p, addr_p,
                                                 UCS_MEMORY_TYPE_ZE_DEVICE,
                                                 UCS_SYS_DEVICE_ID_UNKNOWN, 0,
                                                 "test_ze_copy", memh_p);
        if (status == UCS_ERR_UNSUPPORTED) {
            UCS_TEST_SKIP_R("ZE_DEVICE alloc unsupported on this system");
        }
        if (status != UCS_OK) {
            UCS_TEST_ABORT(
                    "ZE_DEVICE alloc failed: " << ucs_status_string(status));
        }
    }

    /* Base of the import that contains ptr, or NULL when it is not imported */
    static void *import_base(const uct_ze_copy_host_import_t *hi, void *ptr)
    {
        void *base      = NULL;
        ze_result_t ret = hi->get_base(hi->driver, ptr, &base);

        if (ret == ZE_RESULT_SUCCESS) {
            return base;
        }

        EXPECT_EQ(ZE_RESULT_ERROR_INVALID_ARGUMENT, ret);
        return NULL;
    }

    static uct_mem_h mem_reg(uct_md_h md, void *ptr, size_t length)
    {
        uct_md_mem_reg_params_t params = {};
        uct_mem_h memh                 = NULL;

        EXPECT_UCS_OK(uct_md_mem_reg_v2(md, ptr, length, &params, &memh));
        return memh;
    }

    static void mem_dereg(uct_md_h md, uct_mem_h memh)
    {
        uct_md_mem_dereg_params_t params = {};

        params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
        params.memh       = memh;
        EXPECT_UCS_OK(uct_md_mem_dereg_v2(md, &params));
    }

    static constexpr size_t CHUNK = 64 * UCS_KBYTE;
};


UCS_TEST_F(test_ze_copy_md, component_is_registered) {
    EXPECT_STREQ("ze_cpy", uct_ze_copy_component.name);
}


UCS_TEST_F(test_ze_copy_md, query_md_resources_returns_at_least_one) {
    uct_md_resource_desc_t *resources = NULL;
    unsigned num                      = 0;

    EXPECT_UCS_OK(
            uct_ze_copy_component.query_md_resources(&uct_ze_copy_component,
                                                     &resources, &num));
    EXPECT_GE(num, 1u);
    ucs_free(resources);
}


UCS_TEST_F(test_ze_copy_md, open_close_md) {
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    auto *ze_md = ucs_derived_of(md.get(), uct_ze_copy_md_t);
    EXPECT_TRUE(ze_md->ze_device != NULL);
    EXPECT_TRUE(ze_md->ze_context != NULL);
}


UCS_TEST_F(test_ze_copy_md, md_attr_advertises_alloc_caps) {
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    uct_md_attr_v2_t attr;
    attr.field_mask = UINT64_MAX;
    EXPECT_UCS_OK(uct_md_query_v2(md, &attr));

    /* ze_copy MD must be able to allocate ZE memory. */
    EXPECT_NE(0u, attr.alloc_mem_types);
    EXPECT_GT(attr.max_alloc, 0u);
}


/*
 * Allocate ZE_DEVICE memory through the MD, then free it.
 */
UCS_TEST_F(test_ze_copy_md, mem_alloc_free_device) {
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    size_t length  = 4096;
    void *addr     = NULL;
    uct_mem_h memh = NULL;

    alloc_device_or_skip(md, &length, &addr, &memh);
    EXPECT_TRUE(addr != NULL);
    EXPECT_GE(length, 4096u);

    EXPECT_UCS_OK(md->ops->mem_free(md, memh));
}


/*
 * detect_memory_type must classify ZE device pointers as ZE_DEVICE.
 */
UCS_TEST_F(test_ze_copy_md, detect_memory_type_device) {
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    size_t length  = 4096;
    void *addr     = NULL;
    uct_mem_h memh = NULL;
    alloc_device_or_skip(md, &length, &addr, &memh);

    ucs_memory_type_t mem_type = UCS_MEMORY_TYPE_HOST;
    EXPECT_UCS_OK(md->ops->detect_memory_type(md, addr, length, &mem_type));
    EXPECT_EQ(UCS_MEMORY_TYPE_ZE_DEVICE, mem_type);

    EXPECT_UCS_OK(md->ops->mem_free(md, memh));
}


/*
 * The first allocation through this MD must be tracked in the memtype cache.
 */
UCS_TEST_F(test_ze_copy_md, memtype_cache_created_at_md_open) {
    if (ucs_global_opts.enable_memtype_cache == UCS_NO) {
        UCS_TEST_SKIP_R("memtype cache is disabled");
    }

    /* Creation fails permanently once it has failed in this process, so make
     * sure the cache can be created at all; otherwise a NULL instance after
     * uct_md_open() would prove nothing. */
    ucs_memtype_cache_global_create();
    if (ucs_memtype_cache_global_instance == NULL) {
        UCS_TEST_SKIP_R("memtype cache cannot be created");
    }

    /* Drop the cache, so that the MD open has to create it again. */
    ucs_memtype_cache_cleanup();
    ucs_memtype_cache_global_init();
    ASSERT_TRUE(ucs_memtype_cache_global_instance == NULL);

    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    EXPECT_TRUE(ucs_memtype_cache_global_instance != NULL);

    size_t length  = 4096;
    void *addr     = NULL;
    uct_mem_h memh = NULL;
    alloc_device_or_skip(md, &length, &addr, &memh);

    ucs_memory_info_t mem_info;
    ucs_status_t status = ucs_memtype_cache_lookup(addr, length, &mem_info);
    EXPECT_UCS_OK(status);
    if (status == UCS_OK) {
        EXPECT_EQ(UCS_MEMORY_TYPE_ZE_DEVICE, mem_info.type);
    }

    EXPECT_UCS_OK(md->ops->mem_free(md, memh));
    EXPECT_EQ(UCS_ERR_NO_ELEM,
              ucs_memtype_cache_lookup(addr, length, &mem_info));
}


/*
 * mem_query reports base address and allocation length back.
 */
UCS_TEST_F(test_ze_copy_md, mem_query_base_and_length) {
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    size_t length  = 8192;
    void *addr     = NULL;
    uct_mem_h memh = NULL;
    alloc_device_or_skip(md, &length, &addr, &memh);

    uct_md_mem_attr_v2_t mem_attr = {};
    mem_attr.field_mask           = UCT_MD_MEM_ATTR_V2_FIELD_MEM_TYPE |
                                    UCT_MD_MEM_ATTR_V2_FIELD_BASE_ADDRESS |
                                    UCT_MD_MEM_ATTR_V2_FIELD_ALLOC_LENGTH;
    EXPECT_UCS_OK(md->ops->mem_query(md, addr, length, &mem_attr));
    EXPECT_EQ(UCS_MEMORY_TYPE_ZE_DEVICE, mem_attr.mem_type);
    EXPECT_TRUE(mem_attr.base_address != NULL);
    EXPECT_GE(mem_attr.alloc_length, length);

    EXPECT_UCS_OK(md->ops->mem_free(md, memh));
}


/*
 * Registering host memory imports it into the driver; deregistering releases
 * the import.
 */
UCS_TEST_F(test_ze_copy_md, host_import_reg_dereg) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    std::vector<char> buf(2 * CHUNK);
    char *ptr = buf.data();

    uct_mem_h memh = mem_reg(md, ptr, buf.size());
    EXPECT_EQ(ptr, import_base(hi, ptr));
    EXPECT_EQ(ptr, import_base(hi, ptr + buf.size() - 1));

    mem_dereg(md, memh);
    EXPECT_TRUE(import_base(hi, ptr) == NULL);
}


/*
 * Registrations of the same range, and of a range inside it, share one
 * import that stays until the last of them is deregistered, in any order.
 */
UCS_TEST_F(test_ze_copy_md, host_import_shared) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    std::vector<char> buf(2 * CHUNK);
    char *ptr = buf.data();

    for (int reverse = 0; reverse < 2; ++reverse) {
        uct_mem_h whole = mem_reg(md, ptr, buf.size());
        uct_mem_h again = mem_reg(md, ptr, buf.size());
        uct_mem_h inner = mem_reg(md, ptr + (CHUNK / 2), CHUNK);
        EXPECT_EQ(whole, again);
        EXPECT_EQ(whole, inner);

        mem_dereg(md, reverse ? inner : whole);
        EXPECT_EQ(ptr, import_base(hi, ptr));
        mem_dereg(md, again);
        EXPECT_EQ(ptr, import_base(hi, ptr));
        mem_dereg(md, reverse ? whole : inner);
        EXPECT_TRUE(import_base(hi, ptr) == NULL);
    }
}


/*
 * Imports are process-wide: two MDs registering the same range share one
 * import.
 */
UCS_TEST_F(test_ze_copy_md, host_import_shared_by_mds) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md1, md2;
    open_md_or_skip(md1);
    open_md_or_skip(md2);

    std::vector<char> buf(2 * CHUNK);
    char *ptr = buf.data();

    uct_mem_h memh1 = mem_reg(md1, ptr, buf.size());
    uct_mem_h memh2 = mem_reg(md2, ptr, buf.size());
    EXPECT_EQ(memh1, memh2);

    mem_dereg(md1, memh1);
    EXPECT_EQ(ptr, import_base(hi, ptr));
    mem_dereg(md2, memh2);
    EXPECT_TRUE(import_base(hi, ptr) == NULL);
}


/*
 * A range that shares only one end with an existing import is left
 * unimported, and deregistering it must not release that import.
 */
UCS_TEST_F(test_ze_copy_md, host_import_partial_overlap) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    std::vector<char> buf(4 * CHUNK);
    char *ptr    = buf.data();
    char *middle = ptr + CHUNK;

    uct_mem_h middle_memh = mem_reg(md, middle, 2 * CHUNK);
    EXPECT_EQ(middle, import_base(hi, middle));

    /* Ends inside the import */
    uct_mem_h head = mem_reg(md, ptr, 2 * CHUNK);
    /* Starts inside the import */
    uct_mem_h tail = mem_reg(md, ptr + (2 * CHUNK), 2 * CHUNK);
    EXPECT_TRUE(import_base(hi, ptr) == NULL);
    EXPECT_TRUE(import_base(hi, ptr + buf.size() - 1) == NULL);
    EXPECT_EQ(middle, import_base(hi, middle));

    mem_dereg(md, head);
    mem_dereg(md, tail);
    EXPECT_EQ(middle, import_base(hi, middle));

    mem_dereg(md, middle_memh);
    EXPECT_TRUE(import_base(hi, middle) == NULL);
}


/*
 * An import of ours inside a later, larger import of ours: both are owned
 * and released independently, in either order.
 */
UCS_TEST_F(test_ze_copy_md, host_import_nested) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    std::vector<char> buf(3 * CHUNK);
    char *ptr       = buf.data();
    char *inner_ptr = ptr + CHUNK;

    for (int reverse = 0; reverse < 2; ++reverse) {
        uct_mem_h inner = mem_reg(md, inner_ptr, CHUNK);
        uct_mem_h outer = mem_reg(md, ptr, buf.size());
        EXPECT_NE(inner, outer);
        EXPECT_EQ(inner_ptr, import_base(hi, inner_ptr));
        EXPECT_EQ(ptr, import_base(hi, ptr));

        /* A range with one end in each import is left unimported, as the
           driver would reject importing it, and does not borrow either */
        uct_mem_h straddling = mem_reg(md, ptr + (CHUNK / 2), CHUNK);
        EXPECT_NE(straddling, inner);
        EXPECT_NE(straddling, outer);
        mem_dereg(md, straddling);
        EXPECT_EQ(inner_ptr, import_base(hi, inner_ptr));
        EXPECT_EQ(ptr, import_base(hi, ptr));

        mem_dereg(md, reverse ? outer : inner);
        if (reverse) {
            EXPECT_TRUE(import_base(hi, ptr) == NULL);
            EXPECT_EQ(inner_ptr, import_base(hi, inner_ptr));
        } else {
            /* The inner range is now served by the outer import */
            EXPECT_EQ(ptr, import_base(hi, ptr));
            EXPECT_EQ(ptr, import_base(hi, inner_ptr));
        }

        mem_dereg(md, reverse ? inner : outer);
        EXPECT_TRUE(import_base(hi, ptr) == NULL);
        EXPECT_TRUE(import_base(hi, inner_ptr) == NULL);
    }
}


/*
 * Imports made by the application are used but never released: a range
 * inside one borrows it, a range around one gets an import of its own.
 */
UCS_TEST_F(test_ze_copy_md, host_import_foreign) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    std::vector<char> buf(3 * CHUNK);
    char *ptr     = buf.data();
    char *foreign = ptr + CHUNK;

    ASSERT_EQ(ZE_RESULT_SUCCESS, hi->import(hi->driver, foreign, CHUNK));

    uct_mem_h inner = mem_reg(md, foreign + (CHUNK / 4), CHUNK / 2);
    EXPECT_EQ(foreign, import_base(hi, foreign + (CHUNK / 4)));
    mem_dereg(md, inner);
    EXPECT_EQ(foreign, import_base(hi, foreign));

    uct_mem_h outer = mem_reg(md, ptr, buf.size());
    EXPECT_EQ(ptr, import_base(hi, ptr));
    EXPECT_EQ(foreign, import_base(hi, foreign));
    mem_dereg(md, outer);
    EXPECT_TRUE(import_base(hi, ptr) == NULL);
    EXPECT_EQ(foreign, import_base(hi, foreign));

    EXPECT_EQ(ZE_RESULT_SUCCESS, hi->release(hi->driver, foreign));
    EXPECT_TRUE(import_base(hi, foreign) == NULL);
}


/*
 * Level Zero allocations are not imported.
 */
UCS_TEST_F(test_ze_copy_md, host_import_skips_ze_memory) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md);

    size_t length        = CHUNK;
    void *addr           = NULL;
    uct_mem_h alloc_memh = NULL;
    alloc_device_or_skip(md, &length, &addr, &alloc_memh);

    uct_mem_h memh = mem_reg(md, addr, length);
    EXPECT_TRUE(import_base(hi, addr) == NULL);
    mem_dereg(md, memh);

    EXPECT_UCS_OK(md->ops->mem_free(md, alloc_memh));
}


/*
 * HOST_IMPORT=n keeps registrations working without importing.
 */
UCS_TEST_F(test_ze_copy_md, host_import_disabled) {
    const uct_ze_copy_host_import_t *hi = ze_copy_host_import_or_skip();
    ucs::handle<uct_md_h> md;
    open_md_or_skip(md, "n");

    std::vector<char> buf(2 * CHUNK);
    char *ptr = buf.data();

    uct_mem_h memh = mem_reg(md, ptr, buf.size());
    EXPECT_TRUE(import_base(hi, ptr) == NULL);
    mem_dereg(md, memh);
}
