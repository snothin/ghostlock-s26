# Porting Notes

Notes for porting this exploit to another device or firmware version.

## Where parameters live

- **Fixed constants** (shared by all devices): `exploit/src/params.h`
- **Per-kernel-line parameters** and the **build → line map**: `exploit/src/params_table.c`
- **Runtime custom line** (no rebuild): `/data/local/tmp/ghostlock-lines.conf` on the device

A new firmware only needs a new `device_map` entry (`build_id` + `device` + `line_id`).
A new kernel binary (new line) additionally needs the per-line table below re-derived.

## Per-kernel-line parameters (`struct kernel_line`)

### Slide (tracefs)

| Field                       | Source                                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `tracefs_event_id`          | runtime id of the `sched_blocked_reason` trace event — read it from the device tracefs (authoritative) or derive offline from kallsyms |
| `tracefs_worker_caller_off` | kallsyms + disassembly of `worker_thread`: the instruction after the blocking `bl schedule` (the recorded caller is the return PC)     |

### Seed symbols (kallsyms)

| Field                 | Purpose                                       |
| --------------------- | --------------------------------------------- |
| `root_task_group_off` | seeded into the fake task (`task_group` slot) |
| `init_task_off`       | seeded as `waiter_task` / `pi_top_task`       |

### Attr carrier (kallsyms)

| Field                                            | Purpose                                            |
| ------------------------------------------------ | -------------------------------------------------- |
| `misc_list_off`                                  | misc device list head (attach/restore anchor)      |
| `uinput_misc_off`                                | uinput misc node (carrier anchor)                  |
| `simple_attr_read_off` / `simple_attr_write_off` | read/write callbacks of the fake node fops         |
| `debugfs_u64_get_off` / `debugfs_u64_set_off`    | accessor callbacks seeded into the fake misc nodes |
| `debugfs_u64_format_off`                         | rodata `"%llu\n"` string                           |
| `default_llseek_off`                             | llseek slot of the fake fops                       |

### UMH root (kallsyms)

| Field                               | Purpose                                        |
| ----------------------------------- | ---------------------------------------------- |
| `call_usermodehelper_exec_work_off` | forged `work.func`                             |
| `system_unbound_wq_off`             | workqueue topology root — **differs per line** |
| `selinux_enforcing_off`             | `selinux_state.enforcing` (permissive write)   |

### Physical model

| Field         | Meaning                                                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| `phys_offset` | memstart — first DRAM physical address, 1 GiB aligned; `0x80000000` on all three current lines         |
| `phys_load`   | kernel image physical load base; `0xc7800000` on the Snapdragon lines, `0x80000000` on the Exynos line |

## Fixed constants (`params.h`)

`KIMAGE_TEXT_BASE`, `KERNELSNITCH_IDENTITY_START/END`, `DIRECT_MAP_BASE/END`,
`VMEMMAP_START`, `UINPUT_DEVICE` / `UINPUT_MINOR` — stable on the Samsung 6.12
GKI family; re-check only when moving to a new kernel family.

## Layout and BTF constants

- Payload page layout (`LOCK_OFF`/`W0_OFF`/`FAKE_TASK_OFF`/`FOPS_OFF`/attr carrier offsets)
- Kernel struct layouts (`WQ_*`, `PWQ_*`, `POOL_*`, `WORK_*`, `FOPS_*`, `FAKE_WAITER_*`,
  `FAKE_TASK_*`, `MISC_STRUCT_*`): derived from the BTF embedded in the kernel image —
  re-verify with BTF when changing the route or porting to a new kernel family.

## Runtime custom line

When automatic matching fails (or `PARAMS_CUSTOM=1`), the exploit reads one full
line from `/data/local/tmp/ghostlock-lines.conf`: `line_id=...` plus every
`kernel_line` field above as `field=value` (hex or decimal). The file is rejected
unless all fields are present, parse cleanly, and meet their alignment floors
(struct offsets 8 B, function symbols 4 B, `phys_offset` 1 GiB, `phys_load` 2 MiB).
Explicit mode fails closed — no silent fallback to a built-in line.

## Reference values (current targets)

| Field                               | cn         | intl       | exynos     |
| ----------------------------------- | ---------- | ---------- | ---------- |
| `tracefs_event_id`                  | 110        | 110        | 110        |
| `tracefs_worker_caller_off`         | 0x103878   | 0x103878   | 0x1040D4   |
| `root_task_group_off`               | 0x02763580 | 0x02763580 | 0x02772D80 |
| `init_task_off`                     | 0x0252D040 | 0x0252D040 | 0x0253D040 |
| `misc_list_off`                     | 0x0264CFE0 | 0x0264CFE0 | 0x0265CA20 |
| `uinput_misc_off`                   | 0x02671800 | 0x02671800 | 0x02680110 |
| `simple_attr_read_off`              | 0x00484D3C | 0x00484D3C | 0x00486B64 |
| `simple_attr_write_off`             | 0x00484E8C | 0x00484E8C | 0x00486CB4 |
| `debugfs_u64_get_off`               | 0x00675384 | 0x00675384 | 0x00677628 |
| `debugfs_u64_set_off`               | 0x00675398 | 0x00675398 | 0x0067763C |
| `default_llseek_off`                | 0x0043FB54 | 0x0043FB54 | 0x0044173C |
| `debugfs_u64_format_off`            | 0x0148C338 | 0x0148C338 | 0x0148C6B8 |
| `call_usermodehelper_exec_work_off` | 0x000F8F0C | 0x000F8F0C | 0x000F9768 |
| `system_unbound_wq_off`             | 0x01915250 | 0x01914250 | 0x01917250 |
| `selinux_enforcing_off`             | 0x027AFB08 | 0x027AFB08 | 0x027BFAF0 |
| `phys_offset`                       | 0x80000000 | 0x80000000 | 0x80000000 |
| `phys_load`                         | 0xc7800000 | 0xc7800000 | 0x80000000 |

## Sources at a glance

- **kallsyms** — from the boot image kernel: all `*_off` symbol offsets.
- **BTF** — embedded in the kernel image: struct layouts.
- **tracefs** — the `sched_blocked_reason` event id can be read from the device.
- **On-device verification** — `phys_load`/`phys_offset` per line; `UINPUT_MINOR` is
  fixed at 223 on the current family.
