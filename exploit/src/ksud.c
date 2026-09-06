#include "common.h"
#include "ksu_proto.h"
#include <sys/un.h>

int prepare_ksud_stage(void) {
  int rc = ksu_stage_sync(KSU_LOADER_PATH, KSU_STAGE_PATH);
  if (rc < 0) {
    pr_warning("loader stage: sync failed errno=%d\n", errno);
    return -1;
  }
  pr_info("kernelsu loader stage %s\n", rc ? "already present" : "staged");
  return 0;
}

static void ksud_emit_loader_output(const void *buf, size_t len) {
  pr_info("%.*s", (int)len, (const char *)buf);
}

int umh_request_ksu(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", KSU_SOCK_PATH);
  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    close(fd);
    return -1;
  }
  int status = ksu_late_load_exchange(fd, ksud_emit_loader_output);
  close(fd);
  return status;
}
