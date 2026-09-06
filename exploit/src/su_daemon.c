#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

#include "ksu_proto.h"

static volatile sig_atomic_t app_client_terminating;

static void terminate_app_client_group(int signo) {
  if (!app_client_terminating) {
    app_client_terminating = 1;
    pid_t group = getpgrp();
    if (group > 0) {
      kill(-group, SIGKILL);
    }
  }
  _exit(128 + signo);
}

static int install_app_client_lifetime_guard(void) {
  pid_t parent = getppid();
  if (setpgid(0, 0) != 0 && getpgrp() != getpid()) {
    fprintf(stderr, "app client: setpgid failed errno=%d\n", errno);
    return 0;
  }

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  sigemptyset(&action.sa_mask);
  action.sa_handler = terminate_app_client_group;
  action.sa_flags = SA_RESETHAND;
  if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGHUP, &action, NULL) != 0 ||
      sigaction(SIGINT, &action, NULL) != 0) {
    fprintf(stderr, "app client: sigaction failed errno=%d\n", errno);
    return 0;
  }
  if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
    fprintf(stderr, "app client: pr_set_pdeathsig failed errno=%d\n", errno);
    return 0;
  }
  if (parent <= 1 || getppid() != parent) {
    terminate_app_client_group(SIGTERM);
  }
  fprintf(stderr, "app client: lifetime pid=%d pgid=%d ppid=%d\n", getpid(), getpgrp(), parent);
  return 1;
}

static void set_root_env(void) {
  setenv("path",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("home", "/data/local/tmp", 1);
  setenv("user", "root", 1);
  setenv("logname", "root", 1);
}

static int verify_kernelsu_control(void) {
  struct ksu_get_info_cmd info;
  int rc = ksu_probe_control(&info);
  if (rc == -1) {
    dprintf(STDERR_FILENO, "kernelsu driver fd unavailable\n");
    return 0;
  }
  if (rc != 0) {
    dprintf(STDERR_FILENO, "kernelsu control failed errno=%d version=%u flags=0x%x\n", errno,
            info.version, info.flags);
    return 0;
  }
  dprintf(STDOUT_FILENO,
          "kernelsu driver verified version=%u flags=0x%x "
          "(su_allow=%d enable=%d)\n",
          info.version, info.flags, (info.flags & KSU_FLAG_SU_ALLOW) != 0,
          (info.flags & KSU_FLAG_ENABLE) != 0);
  return 1;
}

static int wait_status(pid_t pid) {
  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 1;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static void set_adb_selinux_ctx(void) {
  static const char ctx[] = "u:object_r:system_data_root_file:s0";
  if (setxattr(KSU_ADB_DIR, "security.selinux", ctx, sizeof(ctx), 0) != 0) {
    dprintf(STDERR_FILENO, "late-load: setxattr %s: %s\n", KSU_ADB_DIR, strerror(errno));
  }
}

static void xwrite(int fd, const void *buf, size_t len) {
  if (!proto_write_all(fd, buf, len)) {
    _exit(111);
  }
}

static int refresh_ksud_stage(void) {
  int rc = ksu_stage_sync(KSU_LOADER_PATH, KSU_STAGE_PATH);
  return rc < 0 ? -1 : 0;
}

static int run_kernelsu_late_load(int conn) {
  int pfd[2];
  if (pipe(pfd) != 0) {
    return 1;
  }
  pid_t worker = fork();
  if (worker < 0) {
    close(pfd[0]);
    close(pfd[1]);
    return 1;
  }
  if (worker == 0) {
    close(conn);
    close(pfd[0]);
    dup2(pfd[1], STDOUT_FILENO);
    dup2(pfd[1], STDERR_FILENO);
    if (pfd[1] > STDERR_FILENO) {
      close(pfd[1]);
    }

    set_adb_selinux_ctx();
    if (refresh_ksud_stage() != 0) {
      dprintf(STDERR_FILENO, "late-load: stage refresh failed (%s -> %s)\n", KSU_LOADER_PATH,
              KSU_STAGE_PATH);
    }
    if (unshare(CLONE_NEWNS) != 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: private mount namespace: %s\n", strerror(errno));
      _exit(KSU_LD_NS_FAIL);
    }
    if (mount(KSU_LOADER_PATH, KSU_LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: bind mount: %s\n", strerror(errno));
      _exit(KSU_LD_BIND_FAIL);
    }
    pid_t loader = fork();
    if (loader < 0) {
      _exit(KSU_LD_EXEC_FAIL);
    }
    if (loader == 0) {
      const char *as = getenv("ALLOW_SHELL");
      char *argv_allow[] = {"logcat", "late-load",      "--allow-shell",      "--kmi",
                            KSU_KMI,  "--package-name", "me.weishu.kernelsu", NULL};
      char *argv_norm[] = {"logcat",         "late-load",          "--kmi", KSU_KMI,
                           "--package-name", "me.weishu.kernelsu", NULL};
      execv(KSU_LOGCAT_PATH, (as && as[0] == '1') ? argv_allow : argv_norm);
      dprintf(STDERR_FILENO, "late-load: exec: %s\n", strerror(errno));
      _exit(KSU_LD_EXEC_FAIL);
    }
    int status = wait_status(loader);
    if (status != 0) {
      _exit(status);
    }
    _exit(verify_kernelsu_control() ? 0 : KSU_LD_VERIFY_FAIL);
  }
  close(pfd[1]);

  char buf[4096];
  for (;;) {
    ssize_t n = read(pfd[0], buf, sizeof(buf));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      break;
    }
    uint32_t cl = (uint32_t)n;
    xwrite(conn, &cl, sizeof(cl));
    xwrite(conn, buf, (size_t)n);
  }
  close(pfd[0]);
  int status = wait_status(worker);
  uint32_t end = 0;
  uint32_t st = (uint32_t)status;
  xwrite(conn, &end, sizeof(end));
  xwrite(conn, &st, sizeof(st));
  return status;
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", KSU_SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

static int pump_pair(int a, int b) {
  char buf[4096];
  int a_open = 1;
  int b_open = 1;

  while (a_open || b_open) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (a_open) {
      pfd[nfd].fd = a;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (b_open) {
      pfd[nfd].fd = b;
      pfd[nfd].events = POLLIN;
      nfd++;
    }

    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0 && errno == EINTR) {
      continue;
    }
    if (pr < 0) {
      return 1;
    }

    int idx = 0;
    if (a_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(a, buf, sizeof(buf));
        if (n > 0) {
          xwrite(b, buf, (size_t)n);
        } else {
          a_open = 0;
          shutdown(b, SHUT_WR);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        a_open = 0;
        shutdown(b, SHUT_WR);
      }
    }
    if (b_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(b, buf, sizeof(buf));
        if (n > 0) {
          xwrite(a, buf, (size_t)n);
        } else {
          b_open = 0;
          shutdown(a, SHUT_WR);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        b_open = 0;
        shutdown(a, SHUT_WR);
      }
    }
  }
  return 0;
}

static void su_emit_loader_output(const void *buf, size_t len) {
  (void)write(STDOUT_FILENO, buf, len);
}

static int client_main(int argc, char **argv) {
  int fd = connect_daemon();
  if (fd < 0) {
    return 127;
  }

  if (argc >= 2 && strcmp(argv[1], "-k") == 0) {
    int status = ksu_late_load_exchange(fd, su_emit_loader_output);
    close(fd);
    return status;
  }

  if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
    char mode = 'C';
    uint32_t len = (uint32_t)strlen(argv[2]);
    xwrite(fd, &mode, 1);
    xwrite(fd, &len, sizeof(len));
    xwrite(fd, argv[2], len);
    shutdown(fd, SHUT_WR);

    char buf[4096];
    for (;;) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        break;
      }
      xwrite(STDOUT_FILENO, buf, (size_t)n);
    }
    close(fd);
    return 0;
  }

  char mode = 'I';
  xwrite(fd, &mode, 1);
  int rc = pump_pair(STDIN_FILENO, fd);
  close(fd);
  return rc;
}

static void exec_command_client(int conn, const char *cmd) {
  pid_t pid = fork();
  if (pid == 0) {
    dup2(conn, STDIN_FILENO);
    dup2(conn, STDOUT_FILENO);
    dup2(conn, STDERR_FILENO);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0) {
    close(master);
    return -1;
  }
  if (ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static void exec_interactive_client(int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    const char msg[] = "su daemon: failed to open pty\n";
    xwrite(conn, msg, sizeof(msg) - 1);
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-i", (char *)NULL);
    _exit(127);
  }

  pump_pair(conn, master);
  kill(pid, SIGHUP);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  close(master);
}

static void send_proto_mismatch(int conn, const char *tag) {
  char msg[96];
  int n = snprintf(msg, sizeof(msg),
                   "%s: protocol version mismatch (preload/su_daemon "
                   "out of sync?)\n",
                   tag);
  if (n < 0) {
    return;
  }
  uint32_t cl = (uint32_t)n;
  uint32_t end = 0;
  uint32_t st = (uint32_t)KSU_LD_PROTO_MISMATCH;
  xwrite(conn, &cl, sizeof(cl));
  xwrite(conn, msg, cl);
  xwrite(conn, &end, sizeof(end));
  xwrite(conn, &st, sizeof(st));
}

static void serve_one(int conn) {
  char mode = 0;
  if (!proto_read_exact(conn, &mode, 1)) {
    return;
  }

  if (mode == 'C') {
    uint32_t len = 0;
    if (!proto_read_exact(conn, &len, sizeof(len)) || len > 65536) {
      return;
    }
    char *cmd = calloc(1, (size_t)len + 1);
    if (!cmd) {
      return;
    }
    if (!proto_read_exact(conn, cmd, len)) {
      free(cmd);
      return;
    }
    exec_command_client(conn, cmd);
    free(cmd);
  } else if (mode == 'I') {
    exec_interactive_client(conn);
  } else if (mode == 'K') {
    uint8_t ver = 0;
    if (proto_read_exact(conn, &ver, 1) && ver == KSU_PROTO_VERSION) {
      int status = run_kernelsu_late_load(conn);
      if (status == 0) {
        unlink(KSU_SOCK_PATH);
      }
    } else {
      send_proto_mismatch(conn, "late-load");
    }
  }
}

static void relabel_socket(const char *path) {
  static const char ctx[] = "u:object_r:shell_data_file:s0";
  if (setxattr(path, "security.selinux", ctx, sizeof(ctx), 0) != 0) {
    dprintf(STDERR_FILENO, "relabel socket %s: %s\n", path, strerror(errno));
  }
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  set_root_env();

  if (chmod("/data/local/tmp", 0777) != 0) {
    dprintf(STDERR_FILENO, "daemon: chmod /data/local/tmp: %s\n", strerror(errno));
  }

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }

  unlink(KSU_SOCK_PATH);
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", KSU_SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("bind");
    return 1;
  }
  chmod(KSU_SOCK_PATH, 0666);
  relabel_socket(KSU_SOCK_PATH);
  if (listen(fd, 16) != 0) {
    perror("listen");
    return 1;
  }

  fprintf(stderr, "su daemon ready pid=%d socket=%s uid=%d euid=%d\n", getpid(), KSU_SOCK_PATH,
          getuid(), geteuid());

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      perror("accept");
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

int log_fd;

int main(int argc, char **argv) {
  /* 375 = PSELECT_ROUTE_NFDS(320)+55, the preload log channel; never
   * silently write to fd 0. */
  log_fd = 375;
  dup2(STDOUT_FILENO, log_fd);

  int daemon_mode = argc >= 2 && strcmp(argv[1], "--daemon") == 0;
  if (!daemon_mode && !install_app_client_lifetime_guard()) {
    return 125;
  }
  if (daemon_mode) {
    return daemon_main();
  }
  return client_main(argc, argv);
}
