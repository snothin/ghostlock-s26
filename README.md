# GhostLock (CVE-2026-43499) for the Galaxy S26

CVE-2026-43499 ported to the Samsung Galaxy S26 series — Android 16 / GKI 6.12.
One binary, three kernel lines, dynamic parameter
matching at runtime: theoretically covers the whole S26 series without
per-build compilation.

Most GhostLock porting efforts target a single device or a single firmware.
This repository is a fresh port that rewrites every mechanism for the S26
target and is expected to cover the whole family.

## At a glance

> While maintaining [snothin/CyberMeowfia](https://github.com/snothin/CyberMeowfia),
> I found the original pipe physrw channel unstable (it severed the network), so
> I dropped that route and explored alternatives. Later I found that monovibe
> had gone further along the path I was exploring, adopted the approach, and
> after repeated debugging this repository took shape.

- **Bug**: futex PI use-after-free race → pselect fd_set seeding → one aligned qword
  kernel write → arbitrary kernel read/write.
- **Devices**: Galaxy S26 / S26+ / S26 Ultra, Snapdragon (CN + intl) and Exynos variants.
- **Result**: usermode helper runs as `uid=0(root) context=u:r:kernel:s0`; persistent
  root shell via `su_daemon` on `/data/local/tmp/temp_su.sock`.
- **KDP bypass**: no credential writes — the root stage forges a `work_struct` on
  `system_unbound_wq` whose function is `call_usermodehelper_exec_work`, so the kernel
  executes our daemon with init creds. KDP's EL2 guard on credential pages is never
  triggered.
- **DEFEX bypass**: the ksud late-load is bind-mounted over a dormant system
  binary (`logcat`) before exec; DEFEX's safeplace rule sees a whitelisted path.

## Attack flow

```
tracefs slide oracle → KASLR base
pselect + futex PI race
  → one aligned qword kernel write
  → attr carrier (controller + data misc nodes)
      the write links both nodes
      clearing controller.minor makes the next open land on data
      data fd reads/writes any kernel address
  → UMH root (workqueue injection)
      forged work_struct on system_unbound_wq
      ptmx open/close storm wakes a worker
      kernel execs daemon with init creds
  → KernelSU late-load: ksud bind-mounted over logcat in a private
    mount namespace (DEFEX safeplace sees a whitelisted path)
  → su_daemon keeps serving /data/local/tmp/temp_su.sock
```

## Supported firmware

Parameters are matched by **kernel line** (three lines: `cn`, `intl`, `exynos`), not
by individual build. Unknown OTA builds fall back to the closest known line by model
and CSC. Completely unknown models are rejected (fail-closed). The embedded build
list is authoritative in [`exploit/src/params_table.c`](exploit/src/params_table.c).
A custom kernel line for unlisted firmware can be supplied at runtime
(`/data/local/tmp/ghostlock-lines.conf`, see [Environment](#environment)).
See [PORTING.md](PORTING.md) for the parameters needed when porting to a new
device or firmware.

| Model                      | Device codename | Tested builds                                                                |
| -------------------------- | --------------- | ---------------------------------------------------------------------------- |
| SM-S942x (S26 Snapdragon)  | m1q             | S9420ZCS4AZG1, S942QOPU1AZDE, S942U1UES4AZG3, S942USQS4AZG3                  |
| SM-S947x (S26+ Snapdragon) | m2q             | S9470ZCS4AZG1, S947USQS4AZG3                                                 |
| SM-S9480 (S26 Ultra CN)    | m3q             | S9480ZCS3AZF1, **S9480ZCS4AZG1** (tested build)                              |
| SM-S948x (S26 Ultra)       | m3q             | S9480ZHS4AZG1, S948BXXS4AZG5/6, S948NKSS4AZG3, S948U1UES2AZE1, S948USQS4AZG3 |
| SM-S942B (S26 Exynos)      | m1s             | S942BXXS4AZG5                                                                |
| SM-S947B (S26+ Exynos)     | m2s             | S947BXXS3AZF1, S947BXXS4AZG5                                                 |

## Build

Requires Android NDK (r26+). Just run:

```bash
cd exploit
make preload
# produces build/bin/preload.so (exploit) and build/embed/su_daemon_aarch64_pie (embedded daemon)
```

## Usage

Push `preload.so`, `su_daemon_aarch64_pie` and `ksud` to the device (run from an adb
shell session, uid 2000):

```bash
adb push exploit/build/bin/preload.so /data/local/tmp/
adb push exploit/build/embed/su_daemon_aarch64_pie /data/local/tmp/cve-2026-43499-root
adb push <ksud> /data/local/tmp/ksud
adb shell chmod 755 /data/local/tmp/cve-2026-43499-root /data/local/tmp/ksud

# Single attempt:
adb shell "env LD_PRELOAD=/data/local/tmp/preload.so sh"
```

The exploit is probabilistic (a race) and usually needs repeated attempts. On a
successful run, `su_daemon` listens on `/data/local/tmp/temp_su.sock`, and any
local process can connect.

The boot-claim guard (`/data/local/tmp/ghostlock-boot.log`) records the outcome of
each boot's run; a second full-chain run in the same boot is rejected. Clear the
file or set `BOOT_FORCE=1` to override.

## Environment

Every option exists as an env var, a config-file key
(`/data/local/tmp/ghostlock.conf`, one `key=value` per line) and a CLI flag
(`--key=value`); precedence is defaults < file < env < CLI. Running with
`--help` prints the full table (names, defaults, ranges, reload flags).

The behavior switches:

| Env var              | Key                | Effect                                                                                                          |
| -------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------- |
| `BOOT_FORCE=1`       | `boot.force`       | allow a re-run within the same boot                                                                             |
| `GHOSTLOCK_NO_KSU=1` | `ksu.skip`         | skip the KernelSU late-load: permissive temporary root + su socket only; reboot restores the device (Knox risk) |
| `ALLOW_SHELL=1`      | `root.allow_shell` | add the shell uid to the KernelSU allowlist during late-load                                                    |
| `PARAMS_CUSTOM=1`    | `params.custom`    | use the custom kernel line only (fails closed if unusable)                                                      |

The remaining keys tune the race (`walk.*`, `heap.*`, ...). The exynos line
injects `KSUD_TREE=exynos` for the paired ksud (driver interface 32601); other
lines carry no tree override. Custom kernel lines for unlisted firmware go in
`/data/local/tmp/ghostlock-lines.conf` (`line_id=...` plus one field per line,
see [PORTING.md](PORTING.md)).

## Credits

- **[Nebula Security](https://github.com/NebuSec)** — CVE-2026-43499 discovery
- **polygraphene** — [CyberMeowfia](https://github.com/polygraphene/CyberMeowfia) baseline (first CVE implementation)
- **monovibe** — [s26u-m3q-temp-root](https://github.com/monovibe/s26u-m3q-temp-root): per-child lock regions, UMH root, boot-claim discipline
- **lukasmaar** — [kernelsnitch](https://github.com/lukasmaar/kernelsnitch): mm_struct futex-hash leak (vendored in `exploit/src/kernelsnitch/`)
- **veritas501** — pipe-primitive: pipe CAN_MERGE overwrite concept
- **BuSung-dev** — [Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy): base for the companion app

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

This repository is released under the Apache-2.0 License; see [LICENSE](LICENSE)
for the full text and [NOTICE](NOTICE) for code provenance.
