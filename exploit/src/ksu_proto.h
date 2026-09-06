#ifndef KSU_PROTO_H
#define KSU_PROTO_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KSU_SOCK_PATH "/data/local/tmp/temp_su.sock"
#define KSU_LOADER_PATH "/data/local/tmp/ksud"
#define KSU_STAGE_PATH "/data/local/tmp/.ksud-stage"
#define KSU_ADB_DIR "/data/adb"
#define KSU_LOGCAT_PATH "/system/bin/logcat"
#define KSU_KMI "android16-6.12"

#define KSU_PROTO_VERSION 1U

struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
  uint32_t features;
  uint32_t uapi_version;
};
#define KSU_VERSION_EXPECTED 32601U
#define KSU_FLAG_SU_ALLOW 1U
#define KSU_FLAG_ENABLE 4U

#define KSU_LD_PROTO_MISMATCH (-2)

static inline int ksu_probe_control(struct ksu_get_info_cmd *info_out) {
  int fd = -1;
  syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
  if (fd < 0) {
    return -1;
  }
  struct ksu_get_info_cmd info;
  memset(&info, 0, sizeof(info));
  int ret = ioctl(fd, _IOR('K', 2, struct ksu_get_info_cmd), &info);
  int saved_errno = errno;
  close(fd);
  if (info_out) {
    *info_out = info;
  }
  if (ret != 0 || info.version != KSU_VERSION_EXPECTED || (info.flags & KSU_FLAG_SU_ALLOW) == 0 ||
      (info.flags & KSU_FLAG_ENABLE) == 0) {
    errno = saved_errno;
    return 1;
  }
  return 0;
}

enum {
  KSU_LD_NS_FAIL = 10,
  KSU_LD_BIND_FAIL = 11,
  KSU_LD_EXEC_FAIL = 12,
  KSU_LD_VERIFY_FAIL = 13,
};

static inline int proto_read_exact(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static inline int proto_write_all(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

/* Copy src -> dst unless already in sync; 1 = already present,
 * 0 = freshly staged, -1 = failure. */
static inline int ksu_stage_sync(const char *src, const char *dst) {
  struct stat ss, ds;
  if (stat(dst, &ds) == 0 && stat(src, &ss) == 0 && ds.st_size == ss.st_size) {
    return 1;
  }
  int in = open(src, O_RDONLY | O_CLOEXEC);
  if (in < 0) {
    return -1;
  }
  int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (out < 0) {
    close(in);
    return -1;
  }
  fchmod(out, 0755);
  char buf[8192];
  int ok = 1;
  for (;;) {
    ssize_t n = read(in, buf, sizeof(buf));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      if (n < 0) {
        ok = 0;
      }
      break;
    }
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(out, buf + off, (size_t)(n - off));
      if (w < 0 && errno == EINTR) {
        continue;
      }
      if (w <= 0) {
        ok = 0;
        break;
      }
      off += w;
    }
    if (!ok) {
      break;
    }
  }
  close(in);
  close(out);
  if (!ok) {
    unlink(dst);
    return -1;
  }
  if (stat(dst, &ds) != 0 || stat(src, &ss) != 0 || ds.st_size != ss.st_size) {
    unlink(dst);
    return -1;
  }
  return 0;
}

/* 'K' late-load exchange on a connected fd; loader output chunks go to
 * emit().  Returns the loader status word (0 = loaded; loader failure
 * codes pass through) or -1 on a protocol/IO error. */
static inline int ksu_late_load_exchange(int fd, void (*emit)(const void *buf, size_t len)) {
  const uint8_t req[2] = {'K', (uint8_t)KSU_PROTO_VERSION};
  if (!proto_write_all(fd, req, sizeof(req))) {
    return -1;
  }
  int status = -1;
  for (;;) {
    uint32_t cl = 0;
    if (!proto_read_exact(fd, &cl, sizeof(cl))) {
      break;
    }
    if (cl == 0) {
      uint32_t st = 0;
      if (!proto_read_exact(fd, &st, sizeof(st))) {
        break;
      }
      status = (int)st;
      break;
    }
    if (cl > (1u << 20)) {
      break;
    }
    char buf[8192];
    while (cl) {
      size_t want = cl < sizeof(buf) ? (size_t)cl : sizeof(buf);
      if (!proto_read_exact(fd, buf, want)) {
        return -1;
      }
      emit(buf, want);
      cl -= (uint32_t)want;
    }
  }
  return status;
}

#endif
