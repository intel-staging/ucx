/*
 * Copyright (C) Intel Corporation, 2023-2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ze_ipc_cache.h"
#include "ze_ipc_iface.h"

#include <ucs/arch/atomic.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/pgtable.h>
#include <ucs/debug/log.h>
#include <ucs/profile/profile.h>
#include <ucs/sys/sys.h>
#include <ucs/sys/string.h>
#include <ucs/sys/ptr_arith.h>
#include <ucs/type/spinlock.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>


#define UCT_ZE_IPC_CACHE_INVALID_FD (-1)
#define UCT_ZE_IPC_PROC_PATH_MAX    64


typedef struct uct_ze_ipc_cache uct_ze_ipc_cache_t;
typedef struct uct_ze_ipc_cache_region uct_ze_ipc_cache_region_t;


struct uct_ze_ipc_cache_region {
    ucs_pgt_region_t    super;        /* Base class - page table region */
    ucs_list_link_t     list;         /* List element */
    uct_ze_ipc_rkey_t   key;          /* Remote memory key */
    void                *mapped_addr; /* Local mapped address */
    uint64_t            refcount;     /* Track in-flight ops before unmapping*/
    ze_context_handle_t ze_context;   /* Level Zero context */
    int                 dup_fd;       /* Duplicated file descriptor */
};


struct uct_ze_ipc_cache {
    pthread_rwlock_t lock;    /* Protects the page table */
    ucs_pgtable_t    pgtable; /* Page table to hold the regions */
    char             *name;   /* Name */
};


typedef struct uct_ze_ipc_cache_hash_key {
    pid_t               pid;
    ze_context_handle_t ze_context;
} uct_ze_ipc_cache_hash_key_t;


static UCS_F_ALWAYS_INLINE int
uct_ze_ipc_cache_hash_equal(uct_ze_ipc_cache_hash_key_t key1,
                            uct_ze_ipc_cache_hash_key_t key2)
{
    return (key1.pid == key2.pid) && (key1.ze_context == key2.ze_context);
}

static UCS_F_ALWAYS_INLINE khint32_t
uct_ze_ipc_cache_hash_func(uct_ze_ipc_cache_hash_key_t key)
{
    return kh_int_hash_func((uintptr_t)key.pid ^ (uintptr_t)key.ze_context);
}

KHASH_INIT(ze_ipc_rem_cache, uct_ze_ipc_cache_hash_key_t, uct_ze_ipc_cache_t*,
           1, uct_ze_ipc_cache_hash_func, uct_ze_ipc_cache_hash_equal);

typedef struct uct_ze_ipc_remote_cache {
    khash_t(ze_ipc_rem_cache) hash;
    ucs_recursive_spinlock_t  lock;
} uct_ze_ipc_remote_cache_t;


static uct_ze_ipc_remote_cache_t uct_ze_ipc_remote_cache;

#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
static volatile uint32_t uct_ze_ipc_pidfd_globally_disabled;
#endif

static ucs_status_t
uct_ze_ipc_cache_create(uct_ze_ipc_cache_t **cache, const char *name);

static ucs_pgt_dir_t *
uct_ze_ipc_cache_pgt_dir_alloc(const ucs_pgtable_t *pgtable)
{
    void *ptr;
    int ret;

    ret = ucs_posix_memalign(&ptr,
                             ucs_max(sizeof(void*), UCS_PGT_ENTRY_MIN_ALIGN),
                             sizeof(ucs_pgt_dir_t), "ze_ipc_cache_pgdir");
    return (ret == 0) ? ptr : NULL;
}

static void uct_ze_ipc_cache_pgt_dir_release(const ucs_pgtable_t *pgtable,
                                             ucs_pgt_dir_t *dir)
{
    ucs_free(dir);
}

static void
uct_ze_ipc_cache_region_collect_callback(const ucs_pgtable_t *pgtable,
                                         ucs_pgt_region_t *pgt_region,
                                         void *arg)
{
    ucs_list_link_t *list = arg;
    uct_ze_ipc_cache_region_t *region;

    region = ucs_derived_of(pgt_region, uct_ze_ipc_cache_region_t);
    ucs_list_add_tail(list, &region->list);
}

static UCS_F_ALWAYS_INLINE void
uct_ze_ipc_close_memhandle_safe(ze_context_handle_t ze_context,
                                void **mapped_addr)
{
    ze_result_t ret;

    if ((ze_context == NULL) || (mapped_addr == NULL) ||
        (*mapped_addr == NULL)) {
        return;
    }

    ret = zeMemCloseIpcHandle(ze_context, *mapped_addr);
    if (ret != ZE_RESULT_SUCCESS) {
        ucs_trace("zeMemCloseIpcHandle(ctx %p, addr %p) "
                  "returned 0x%x during cleanup",
                  (void*)ze_context, *mapped_addr, ret);
    }

    *mapped_addr = NULL;
}

static void uct_ze_ipc_cache_purge(uct_ze_ipc_cache_t *cache)
{
    uct_ze_ipc_cache_region_t *region, *tmp;
    ucs_list_link_t region_list;

    ucs_list_head_init(&region_list);
    ucs_pgtable_purge(&cache->pgtable, uct_ze_ipc_cache_region_collect_callback,
                      &region_list);
    ucs_list_for_each_safe(region, tmp, &region_list, list) {
        uct_ze_ipc_close_memhandle_safe(region->ze_context,
                                        &region->mapped_addr);
        if (region->dup_fd >= 0) {
            close(region->dup_fd);
        }

        ucs_free(region);
    }
    ucs_trace("%s: ze ipc cache purged", cache->name);
}

static int uct_ze_ipc_dup_fd_from_pid(uct_ze_ipc_iface_t *iface,
                                      pid_t remote_pid, int remote_fd)
{
    pid_t self = getpid();
#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
    khiter_t iter;
    int pidfd;
    int khret;
#endif
    int local_fd;
    int flags;
    char path[UCT_ZE_IPC_PROC_PATH_MAX];

    if (remote_fd < 0) {
        return UCT_ZE_IPC_CACHE_INVALID_FD;
    }

    /* Same process: simple duplication, trust DMA-BUF FD validity */
    if (remote_pid == self) {
        local_fd = fcntl(remote_fd, F_DUPFD_CLOEXEC, 0);
        if (local_fd < 0) {
            ucs_debug("fcntl(DUPFD_CLOEXEC) failed for fd %d: %m", remote_fd);
            return UCT_ZE_IPC_CACHE_INVALID_FD;
        }
        return local_fd;
    }

    /* Cross-process: try pidfd with caching (Linux 5.6+) */
#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
    if (ucs_atomic_fadd32(&uct_ze_ipc_pidfd_globally_disabled, 0)) {
        goto fallback_proc;
    }

    if (!iface || !iface->pidfd_cache) {
        goto fallback_proc;
    }

    /* Lookup cached pidfd */
    iter = kh_get(ze_ipc_pidfd_cache, iface->pidfd_cache, remote_pid);

    if (iter == kh_end(iface->pidfd_cache)) {
        /* Cache miss: open new pidfd */
        pidfd = syscall(__NR_pidfd_open, remote_pid, 0);
        if (pidfd < 0) {
            if (errno == ENOSYS) {
                if (ucs_atomic_swap32(&uct_ze_ipc_pidfd_globally_disabled, 1) ==
                    0) {
                    ucs_debug("pidfd_open not implemented (ENOSYS), "
                              "disabling pidfd path globally");
                }
            }

            if (errno == EPERM) {
                ucs_debug("pidfd_open(%d) denied: check ptrace permissions "
                          "and /proc/sys/kernel/yama/ptrace_scope; "
                          "falling back to /proc",
                          (int)remote_pid);
            }

            goto fallback_proc; /* pidfd_open failed, try /proc */
        }

        /* Cache the pidfd */
        iter = kh_put(ze_ipc_pidfd_cache, iface->pidfd_cache, remote_pid,
                      &khret);
        if (khret < 0) {
            close(pidfd);
            goto fallback_proc; /* hash error, try /proc */
        }

        kh_value(iface->pidfd_cache, iter) = pidfd;
        ucs_debug("Cached pidfd=%d for pid %d", pidfd, remote_pid);
    } else {
        pidfd = kh_value(iface->pidfd_cache, iter);
    }

    /* Duplicate fd using cached pidfd (single syscall!) */
    local_fd = syscall(__NR_pidfd_getfd, pidfd, remote_fd, 0);
    if (local_fd >= 0) {
        /* Success - set CLOEXEC and return (DMA-BUF FDs are always O_RDWR) */
        fcntl(local_fd, F_SETFD, FD_CLOEXEC);
        return local_fd;
    }

    /* pidfd_getfd failed - remote process likely exited */
    if (errno == ESRCH || errno == EPERM) {
        if (errno == EPERM) {
            ucs_debug("pidfd_getfd denied for pid %d fd %d: check ptrace "
                      "permissions and /proc/sys/kernel/yama/ptrace_scope",
                      remote_pid, remote_fd);
        }

        ucs_debug("pidfd_getfd failed (pid %d exited?), removing from cache",
                  remote_pid);
        close(pidfd);
        kh_del(ze_ipc_pidfd_cache, iface->pidfd_cache, iter);
    }

    /* Fall through to /proc fallback */

fallback_proc:
#endif

    /* Fallback: /proc filesystem - validate O_RDWR (LSM can restrict) */
    ucs_snprintf_safe(path, sizeof(path), "/proc/%d/fd/%d", (int)remote_pid,
                      remote_fd);

    local_fd = open(path, O_RDWR | O_CLOEXEC);
    if (local_fd < 0) {
        ucs_debug("open(%s) failed: %m", path);
        return UCT_ZE_IPC_CACHE_INVALID_FD;
    }

    /* Verify LSM didn't restrict access mode */
    flags = fcntl(local_fd, F_GETFL);
    if ((flags & O_ACCMODE) != O_RDWR) {
        ucs_debug("/proc fd is not O_RDWR (flags=0x%x), rejecting", flags);
        close(local_fd);
        return UCT_ZE_IPC_CACHE_INVALID_FD;
    }

    return local_fd;
}

static ucs_status_t uct_ze_ipc_open_memhandle(uct_ze_ipc_iface_t *iface,
                                              const uct_ze_ipc_rkey_t *key,
                                              ze_context_handle_t ze_context,
                                              ze_device_handle_t ze_device,
                                              void **mapped_addr, int *dup_fd)
{
    ze_ipc_mem_handle_t local_handle;
    ucs_status_t status;
    int remote_fd;

    memcpy(&local_handle, &key->ph, sizeof(local_handle));
    remote_fd = *(int*)local_handle.data;

    /* Duplicate fd if crossing process boundary */
    if (key->pid != getpid() && remote_fd > 0) {
        *dup_fd = uct_ze_ipc_dup_fd_from_pid(iface, key->pid, remote_fd);
        if (*dup_fd < 0) {
            ucs_error("failed to duplicate fd %d from pid %d", remote_fd,
                      key->pid);
            return UCS_ERR_IO_ERROR;
        }

        *(int*)local_handle.data = *dup_fd;
    } else {
        *dup_fd = UCT_ZE_IPC_CACHE_INVALID_FD;
    }

    status = UCT_ZE_FUNC_LOG_ERR(zeMemOpenIpcHandle(ze_context, ze_device,
                                                    local_handle, 0,
                                                    mapped_addr));
    if (status != UCS_OK) {
        ucs_debug("zeMemOpenIpcHandle context: pid %d dev_num %d "
                  "base 0x%lx ctx %p dev %p fd %d",
                  (int)key->pid, key->dev_num, key->d_bptr, (void*)ze_context,
                  (void*)ze_device, *(int*)local_handle.data);

        if (*dup_fd >= 0) {
            close(*dup_fd);
            *dup_fd = UCT_ZE_IPC_CACHE_INVALID_FD;
        }

        return UCS_ERR_IO_ERROR;
    }

    return UCS_OK;
}

static void uct_ze_ipc_cache_invalidate_regions(uct_ze_ipc_cache_t *cache,
                                                void *from, void *to)
{
    ucs_list_link_t region_list;
    ucs_status_t status;
    uct_ze_ipc_cache_region_t *region, *tmp;

    ucs_list_head_init(&region_list);
    ucs_pgtable_search_range(&cache->pgtable, (ucs_pgt_addr_t)from,
                             (ucs_pgt_addr_t)to - 1,
                             uct_ze_ipc_cache_region_collect_callback,
                             &region_list);
    ucs_list_for_each_safe(region, tmp, &region_list, list) {
        status = ucs_pgtable_remove(&cache->pgtable, &region->super);
        if (status != UCS_OK) {
            ucs_error("failed to remove address: %p from cache (%s)",
                      (void*)region->key.d_bptr, ucs_status_string(status));
        }

        uct_ze_ipc_close_memhandle_safe(region->ze_context,
                                        &region->mapped_addr);
        if (region->dup_fd >= 0) {
            close(region->dup_fd);
        }

        ucs_free(region);
    }

    ucs_trace("%s: closed memhandles in the range [%p..%p]", cache->name, from,
              to);
}

static ucs_status_t uct_ze_ipc_get_remote_cache(pid_t pid,
                                                ze_context_handle_t ze_context,
                                                uct_ze_ipc_cache_t **cache)
{
    ucs_status_t status = UCS_OK;
    uct_ze_ipc_cache_hash_key_t key;
    khiter_t khiter;
    int khret;
    char target_name[UCT_ZE_IPC_PROC_PATH_MAX];

    ucs_recursive_spin_lock(&uct_ze_ipc_remote_cache.lock);

    key.ze_context = ze_context;
    key.pid        = pid;

    khiter = kh_put(ze_ipc_rem_cache, &uct_ze_ipc_remote_cache.hash, key,
                    &khret);
    if ((khret == UCS_KH_PUT_BUCKET_EMPTY) ||
        (khret == UCS_KH_PUT_BUCKET_CLEAR)) {
        ucs_snprintf_safe(target_name, sizeof(target_name), "dest:%d:%p",
                          key.pid, key.ze_context);
        status = uct_ze_ipc_cache_create(cache, target_name);
        if (status != UCS_OK) {
            kh_del(ze_ipc_rem_cache, &uct_ze_ipc_remote_cache.hash, khiter);
            ucs_error("could not create ze ipc cache: %s",
                      ucs_status_string(status));
            goto err_unlock;
        }

        kh_val(&uct_ze_ipc_remote_cache.hash, khiter) = *cache;
    } else if (khret == UCS_KH_PUT_KEY_PRESENT) {
        *cache = kh_val(&uct_ze_ipc_remote_cache.hash, khiter);
    } else {
        ucs_error("failed to insert into ze ipc remote cache hash "
                  "(pid %d, context %p): khash error %d",
                  (int)pid, (void*)ze_context, khret);
        status = UCS_ERR_NO_RESOURCE;
    }

err_unlock:
    ucs_recursive_spin_unlock(&uct_ze_ipc_remote_cache.lock);
    return status;
}

ucs_status_t uct_ze_ipc_unmap_memhandle(pid_t pid, uintptr_t address,
                                        void *mapped_addr,
                                        ze_context_handle_t ze_context,
                                        int dup_fd, int cache_enabled)
{
    ucs_status_t status = UCS_OK;
    int needs_remove    = 0;
    uct_ze_ipc_cache_t *cache;
    ucs_pgt_region_t *pgt_region;
    uct_ze_ipc_cache_region_t *region;
    uint64_t old_count;
    uint64_t current_ref;

    (void)dup_fd; /* unused */

    status = uct_ze_ipc_get_remote_cache(pid, ze_context, &cache);
    if (status != UCS_OK) {
        return status;
    }

    /* PHASE 1: Lookup under read lock + CAS decrement.
     * Use compare-swap loop to preserve the invariant that refcount is never
     * decremented from zero. This may retry under contention; if retries become
     * a measured bottleneck, reevaluate the fetch-add variant with underflow
     * handling.
     */
    pthread_rwlock_rdlock(&cache->lock);
    pgt_region = ucs_pgtable_lookup(&cache->pgtable, address);
    if (pgt_region == NULL) {
        pthread_rwlock_unlock(&cache->lock);
        ucs_warn("address %p not found in cache", (void*)address);
        return UCS_ERR_NO_ELEM;
    }

    region = ucs_derived_of(pgt_region, uct_ze_ipc_cache_region_t);
    do {
        old_count = ucs_atomic_fadd64(&region->refcount, 0);
        if (ucs_unlikely(old_count == 0)) {
            pthread_rwlock_unlock(&cache->lock);
            ucs_error("refcount underflow for address %p", (void*)address);
            return UCS_ERR_INVALID_PARAM;
        }
    } while (ucs_atomic_cswap64(
        &region->refcount, old_count, old_count - 1) != old_count);

    if (old_count == 1) {
        needs_remove = !cache_enabled;
    }

    pthread_rwlock_unlock(&cache->lock);

    /* PHASE 2: Removal under write lock with verification */
    if (needs_remove) {
        pthread_rwlock_wrlock(&cache->lock);
        pgt_region = ucs_pgtable_lookup(&cache->pgtable, address);
        if (pgt_region != NULL) {
            region = ucs_derived_of(pgt_region, uct_ze_ipc_cache_region_t);
            current_ref = ucs_atomic_fadd64(&region->refcount, 0);
            if ((region->mapped_addr == mapped_addr) &&
                (current_ref == 0)) {
                status = ucs_pgtable_remove(&cache->pgtable, &region->super);
                pthread_rwlock_unlock(&cache->lock);

                if (status != UCS_OK) {
                    ucs_error("failed to remove address %p: %s",
                              (void*)address, ucs_status_string(status));
                    return status;
                }

                uct_ze_ipc_close_memhandle_safe(region->ze_context,
                                                &region->mapped_addr);
                if (region->dup_fd >= 0) {
                    close(region->dup_fd);
                }

                ucs_free(region);
                return UCS_OK;
            }

            ucs_debug("skipping removal: mapped_addr/refcount mismatch "
                      "(addr=%p, expected=%p, refcount=%" PRIu64 ")",
                      (void*)address, mapped_addr, current_ref);
        }
        pthread_rwlock_unlock(&cache->lock);
    }

    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_ze_ipc_map_memhandle,
                 (iface, key, ze_context, ze_device, mapped_addr, dup_fd),
                 uct_ze_ipc_iface_t *iface, const uct_ze_ipc_rkey_t *key,
                 ze_context_handle_t ze_context, ze_device_handle_t ze_device,
                 void **mapped_addr, int *dup_fd)
{
    ucs_status_t status = UCS_OK;
    ucs_pgt_region_t *pgt_region;
    uct_ze_ipc_cache_t *cache;
    uct_ze_ipc_cache_region_t *region;
    int ret;

    status = uct_ze_ipc_get_remote_cache(key->pid, ze_context, &cache);
    if (status != UCS_OK) {
        return status;
    }

    pthread_rwlock_wrlock(&cache->lock);
    pgt_region = UCS_PROFILE_CALL(ucs_pgtable_lookup, &cache->pgtable,
                                  key->d_bptr);
    if (ucs_likely(pgt_region != NULL)) {
        region = ucs_derived_of(pgt_region, uct_ze_ipc_cache_region_t);

        /* cache hit */
        ucs_trace("%s: ze_ipc cache hit addr: %p size: %lu "
                  "region:" UCS_PGT_REGION_FMT,
                  cache->name, (void*)key->d_bptr, key->b_len,
                  UCS_PGT_REGION_ARG(&region->super));

        *mapped_addr = region->mapped_addr;
        *dup_fd      = region->dup_fd;
        ucs_assert(region->refcount < UINT64_MAX);
        region->refcount++;
        pthread_rwlock_unlock(&cache->lock);
        return UCS_OK;
    }

    /* Open new IPC handle */
    status = uct_ze_ipc_open_memhandle(iface, key, ze_context, ze_device,
                                       mapped_addr, dup_fd);
    if (ucs_unlikely(status != UCS_OK)) {
        goto err_unlock;
    }

    /* Allocate cache entry */
    ret = ucs_posix_memalign((void**)&region,
                             ucs_max(sizeof(void*), UCS_PGT_ENTRY_MIN_ALIGN),
                             sizeof(uct_ze_ipc_cache_region_t),
                             "uct_ze_ipc_cache_region");
    if (ret != 0) {
        ucs_error("failed to allocate cache region: %m");
        status = UCS_ERR_NO_MEMORY;
        goto err_close_handle;
    }

    region->super.start = ucs_align_down_pow2((uintptr_t)key->d_bptr,
                                              UCS_PGT_ADDR_ALIGN);
    region->super.end   = ucs_align_up_pow2((uintptr_t)key->d_bptr +
                                            key->b_len, UCS_PGT_ADDR_ALIGN);
    region->key         = *key;
    region->mapped_addr = *mapped_addr;
    region->refcount    = 1;
    region->ze_context  = ze_context;
    region->dup_fd      = *dup_fd;

    status = UCS_PROFILE_CALL(ucs_pgtable_insert, &cache->pgtable,
                              &region->super);
    if (status == UCS_ERR_ALREADY_EXISTS) {
        uct_ze_ipc_cache_invalidate_regions(cache, (void*)region->super.start,
                                            (void*)region->super.end);
        status = UCS_PROFILE_CALL(ucs_pgtable_insert, &cache->pgtable,
                                  &region->super);
    }

    if (status != UCS_OK) {
        ucs_error("%s: failed to insert region: %s", cache->name,
                  ucs_status_string(status));
        ucs_free(region);
        goto err_close_handle;
    }

    ucs_trace("%s: ze_ipc cache new region:" UCS_PGT_REGION_FMT " size:%lu",
              cache->name, UCS_PGT_REGION_ARG(&region->super), key->b_len);

    pthread_rwlock_unlock(&cache->lock);
    return UCS_OK;

err_close_handle:
    uct_ze_ipc_close_memhandle_safe(ze_context, mapped_addr);
    if (*dup_fd >= 0) {
        close(*dup_fd);
        *dup_fd = UCT_ZE_IPC_CACHE_INVALID_FD;
    }

err_unlock:
    pthread_rwlock_unlock(&cache->lock);
    return status;
}

static ucs_status_t
uct_ze_ipc_cache_create(uct_ze_ipc_cache_t **cache, const char *name)
{
    ucs_status_t status;
    uct_ze_ipc_cache_t *cache_desc;
    int ret;

    cache_desc = ucs_malloc(sizeof(uct_ze_ipc_cache_t), "uct_ze_ipc_cache_t");
    if (cache_desc == NULL) {
        ucs_error("failed to allocate ze ipc cache");
        return UCS_ERR_NO_MEMORY;
    }

    ret = pthread_rwlock_init(&cache_desc->lock, NULL);
    if (ret) {
        ucs_error("pthread_rwlock_init() failed: %m");
        status = UCS_ERR_INVALID_PARAM;
        goto err;
    }

    status = ucs_pgtable_init(&cache_desc->pgtable,
                              uct_ze_ipc_cache_pgt_dir_alloc,
                              uct_ze_ipc_cache_pgt_dir_release);
    if (status != UCS_OK) {
        ucs_error("failed to initialize page table: %s",
                  ucs_status_string(status));
        goto err_destroy_rwlock;
    }

    cache_desc->name = ucs_strdup(name, "ze_ipc_cache_name");
    if (cache_desc->name == NULL) {
        ucs_error("failed to duplicate cache name '%s'", name);
        status = UCS_ERR_NO_MEMORY;
        goto err_cleanup_pgtable;
    }

    *cache = cache_desc;
    return UCS_OK;

err_cleanup_pgtable:
    ucs_pgtable_cleanup(&cache_desc->pgtable);
err_destroy_rwlock:
    pthread_rwlock_destroy(&cache_desc->lock);
err:
    ucs_free(cache_desc);
    return status;
}

static void uct_ze_ipc_cache_destroy(uct_ze_ipc_cache_t *cache)
{
    uct_ze_ipc_cache_purge(cache);
    ucs_pgtable_cleanup(&cache->pgtable);
    pthread_rwlock_destroy(&cache->lock);
    ucs_free(cache->name);
    ucs_free(cache);
}

UCS_STATIC_INIT
{
    ucs_recursive_spinlock_init(&uct_ze_ipc_remote_cache.lock, 0);
    kh_init_inplace(ze_ipc_rem_cache, &uct_ze_ipc_remote_cache.hash);
}

UCS_STATIC_CLEANUP
{
    uct_ze_ipc_cache_t *rem_cache;

    kh_foreach_value(&uct_ze_ipc_remote_cache.hash, rem_cache,
                     { uct_ze_ipc_cache_destroy(rem_cache); })
        kh_destroy_inplace(ze_ipc_rem_cache, &uct_ze_ipc_remote_cache.hash);
    ucs_recursive_spinlock_destroy(&uct_ze_ipc_remote_cache.lock);
}
