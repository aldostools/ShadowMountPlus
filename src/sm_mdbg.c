#include "sm_platform.h"

#include <inttypes.h>
#include <stdlib.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include "sm_config_mount.h"
#include "sm_limits.h"
#include "sm_log.h"
#include "sm_mdbg.h"
#include "sm_time.h"
#include "sm_types.h"

#define SCE_AUTHID_COREDUMP 0x4800000000000006ull
#define SYS_mdbg_call 573

#define MDBG_CMD_TYPE_SERVICE 1ull
#define MDBG_CMD_PROCESS_STATE 30ull
#define MDBG_SUBCMD_FLAGS 2ull
#define MDBG_SUBCMD_STATE3 16ull

#define MDBG_FLAG_EXCEPTION_STOP 0x00080000ull
#define MDBG_AUTOTUNE_WINDOW_US (300ull * 1000000ull)
#define KLOG_DEVICE_PATH "/dev/klog"
#define KLOG_POLL_CHUNK_SIZE 512u
#define KLOG_LINE_BUFFER_SIZE 512u

typedef struct {
  uint64_t type;
  uint64_t cmd;
} mdbg_cmd_t;

typedef struct {
  int64_t pid;
  int64_t subcmd;
  uint64_t arg;
  uint64_t reserved[5];
} mdbg_req_t;

typedef struct {
  int64_t status;
  uint64_t value;
  uint64_t reserved[2];
} mdbg_res_t;

typedef struct {
  bool active;
  bool klog_monitoring_active;
  bool pause_seen;
  pid_t pid;
  uint32_t pause_delay_seconds;
  uint64_t monitor_deadline_us;
  uint64_t pause_time_us;
  uint64_t next_poll_us;
  char title_id[MAX_TITLE_ID];
  char comm[32];
} mdbg_game_state_t;

typedef struct {
  bool privilege_probe_done;
  bool privilege_ready;
  bool klog_open_failed_logged;
  int klog_fd;
  size_t klog_line_length;
  char klog_line[KLOG_LINE_BUFFER_SIZE];
  mdbg_game_state_t game;
} sm_mdbg_state_t;

static sm_mdbg_state_t g_mdbg;

static bool sm_mdbg_enabled(void);
static int elevate_to_coredump(void);
static bool ensure_mdbg_privileges(void);
static int mdbg_call_raw(int64_t pid, uint64_t subcmd, uint64_t arg,
                         int64_t *status_out, uint64_t *value_out);
static int query_mdbg_flags(pid_t pid, uint64_t *flags_out);
static int query_mdbg_state3(pid_t pid, uint32_t *state_flags_out,
                             uint32_t *stop_reason_out);
static bool read_proc_info(pid_t pid, struct kinfo_proc *ki);
static bool is_mdbg_process_gone_error(int ret);
static void reset_tracked_game(mdbg_game_state_t *game);
static void reset_klog_buffer(void);
static bool open_klog_device(void);
static void close_klog_device(void);
static void clear_tracked_game(void);
static void capture_process_comm(const struct kinfo_proc *ki);
static bool parse_klog_rtld_error(const char *line, pid_t *pid_out);
static bool klog_line_matches_tracked_load_error(const char *line);
static bool reason_is_rtld_error(const char *reason);
static void summarize_failure_reason(const char *reason, char *summary_out,
                                     size_t summary_out_size);
static void handle_pre_pause_failure(const char *reason);
static void handle_post_pause_failure(const char *reason, uint64_t now_us);
static void process_klog_line(const char *line, uint64_t now_us);
static void append_klog_char(char ch, uint64_t now_us);
static void drain_klog_monitor(void);
static void poll_klog_monitor(uint64_t now_us);
static void start_klog_monitoring(void);
static void handle_crash_candidate(uint64_t flags, uint32_t state_flags,
                                   uint32_t stop_reason, uint64_t now_us);

static bool sm_mdbg_enabled(void) {
  return runtime_config()->kstuff_crash_detection_enabled &&
         runtime_config()->kstuff_game_auto_toggle;
}

static int elevate_to_coredump(void) {
  static const uint8_t k_priv_caps[16] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  pid_t pid = getpid();

  if (kernel_set_ucred_authid(pid, SCE_AUTHID_COREDUMP) < 0)
    return -1;
  if (kernel_set_ucred_caps(pid, k_priv_caps) < 0)
    return -1;

  return 0;
}

static bool ensure_mdbg_privileges(void) {
  if (g_mdbg.privilege_probe_done)
    return g_mdbg.privilege_ready;

  g_mdbg.privilege_probe_done = true;
  g_mdbg.privilege_ready = elevate_to_coredump() == 0;
  if (g_mdbg.privilege_ready) {
    log_debug("  [MDBG] coredump privileges enabled");
  } else {
    log_debug("  [MDBG] failed to enable coredump privileges; mdbg polling "
              "disabled, klog monitoring will continue");
  }

  return g_mdbg.privilege_ready;
}

static int mdbg_call_raw(int64_t pid, uint64_t subcmd, uint64_t arg,
                         int64_t *status_out, uint64_t *value_out) {
  mdbg_cmd_t cmd = {MDBG_CMD_TYPE_SERVICE, MDBG_CMD_PROCESS_STATE};
  mdbg_req_t req;
  mdbg_res_t res;
  long syscall_ret;

  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.pid = pid;
  req.subcmd = (int64_t)subcmd;
  req.arg = arg;

  syscall_ret = syscall(SYS_mdbg_call, &cmd, &req, &res);
  if (syscall_ret == -1)
    return errno ? -errno : -1;

  if (status_out)
    *status_out = res.status;
  if (value_out)
    *value_out = res.value;
  return 0;
}

static int query_mdbg_flags(pid_t pid, uint64_t *flags_out) {
  int64_t status;
  uint64_t value;
  int ret = mdbg_call_raw(pid, MDBG_SUBCMD_FLAGS, 0, &status, &value);
  if (ret < 0)
    return ret;
  if (status != 0)
    return (int)status;
  if (flags_out)
    *flags_out = value;
  return 0;
}

static int query_mdbg_state3(pid_t pid, uint32_t *state_flags_out,
                             uint32_t *stop_reason_out) {
  int64_t status;
  uint64_t value;
  int ret = mdbg_call_raw(pid, MDBG_SUBCMD_STATE3, 3, &status, &value);
  if (ret < 0)
    return ret;
  if (status != 0)
    return (int)status;

  if (state_flags_out) {
    uint32_t state_flags = (uint32_t)(value & 7u);
    if ((value & 0x10u) != 0)
      state_flags |= 8u;
    *state_flags_out = state_flags;
  }
  if (stop_reason_out)
    *stop_reason_out = (uint32_t)(value >> 32);

  return 0;
}

static bool read_proc_info(pid_t pid, struct kinfo_proc *ki) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
  size_t buf_size;

  if (!ki || pid <= 0)
    return false;

  memset(ki, 0, sizeof(*ki));
  buf_size = sizeof(*ki);
  if (sysctl(mib, 4, ki, &buf_size, NULL, 0) < 0)
    return false;

  return buf_size >= sizeof(*ki) && ki->ki_pid == pid;
}

static bool is_mdbg_process_gone_error(int ret) {
  return ret == -ESRCH || ret == -ENOENT || ret == ESRCH || ret == ENOENT;
}

static void reset_tracked_game(mdbg_game_state_t *game) {
  if (!game)
    return;

  memset(game, 0, sizeof(*game));
}

static void reset_klog_buffer(void) {
  g_mdbg.klog_line_length = 0;
  g_mdbg.klog_line[0] = '\0';
}

static bool open_klog_device(void) {
  if (g_mdbg.klog_fd >= 0)
    return true;

  int open_flags = O_RDONLY | O_NONBLOCK;
#ifdef O_SHLOCK
  open_flags |= O_SHLOCK;
#endif

  int fd = open(KLOG_DEVICE_PATH, open_flags);
  if (fd < 0) {
    if (!g_mdbg.klog_open_failed_logged) {
      log_debug("  [MDBG] failed to open %s for %s: %s", KLOG_DEVICE_PATH,
                g_mdbg.game.title_id[0] != '\0' ? g_mdbg.game.title_id : "?",
                strerror(errno));
      g_mdbg.klog_open_failed_logged = true;
    }
    return false;
  }

  g_mdbg.klog_fd = fd;
  g_mdbg.klog_open_failed_logged = false;
  return true;
}

static void close_klog_device(void) {
  if (g_mdbg.klog_fd < 0)
    return;

  close(g_mdbg.klog_fd);
  g_mdbg.klog_fd = -1;
  reset_klog_buffer();
  g_mdbg.klog_open_failed_logged = false;
}

static void clear_tracked_game(void) {
  reset_tracked_game(&g_mdbg.game);
  reset_klog_buffer();
}

static void capture_process_comm(const struct kinfo_proc *ki) {
  if (!ki)
    return;

  (void)strlcpy(g_mdbg.game.comm, ki->ki_comm, sizeof(g_mdbg.game.comm));
}

static bool parse_klog_rtld_error(const char *line, pid_t *pid_out) {
  if (!line || line[0] == '\0')
    return false;

  if (strstr(line, "[rtld]") == NULL || strstr(line, "ERROR") == NULL)
    return false;

  const char *open = strchr(line, '<');
  if (!open)
    return false;

  char *end = NULL;
  long parsed_pid = strtol(open + 1, &end, 10);
  if (end == open + 1 || !end || *end != '>' || parsed_pid <= 0)
    return false;

  if (pid_out)
    *pid_out = (pid_t)parsed_pid;

  return true;
}

static bool klog_line_matches_tracked_load_error(const char *line) {
  pid_t line_pid = 0;
  return parse_klog_rtld_error(line, &line_pid) && g_mdbg.game.active &&
         g_mdbg.game.pid == line_pid;
}

static bool reason_is_rtld_error(const char *reason) {
  return parse_klog_rtld_error(reason, NULL);
}

static void summarize_failure_reason(const char *reason, char *summary_out,
                                     size_t summary_out_size) {
  if (!summary_out || summary_out_size == 0)
    return;

  summary_out[0] = '\0';
  if (!reason || reason[0] == '\0')
    return;

  if (reason_is_rtld_error(reason)) {
    const char *open_paren = strrchr(reason, '(');
    const char *close_paren =
        open_paren ? strchr(open_paren + 1, ')') : NULL;
    if (open_paren && close_paren && close_paren > open_paren + 1) {
      int written = snprintf(summary_out, summary_out_size,
                             "can't load module %.*s after KStuff pause",
                             (int)(close_paren - open_paren - 1),
                             open_paren + 1);
      if (written > 0 && (size_t)written < summary_out_size)
        return;
    }

    (void)strlcpy(summary_out, "can't load module after KStuff pause",
                  summary_out_size);
    return;
  }

  (void)strlcpy(summary_out, reason, summary_out_size);
}

static void handle_pre_pause_failure(const char *reason) {
  log_debug("  [MDBG] %s crashed before kstuff auto-pause%s%s",
            g_mdbg.game.title_id, reason ? ": " : "", reason ? reason : "");
  notify_system_info("App crashed before KStuff pause: %s. KStuff is not to "
                     "blame.",
                     g_mdbg.game.title_id);
  clear_tracked_game();
}

static void handle_post_pause_failure(const char *reason, uint64_t now_us) {
  if (!g_mdbg.game.pause_seen || g_mdbg.game.pause_time_us == 0 ||
      now_us < g_mdbg.game.pause_time_us) {
    handle_pre_pause_failure(reason);
    return;
  }

  uint64_t post_pause_us = now_us - g_mdbg.game.pause_time_us;
  if (post_pause_us > MDBG_AUTOTUNE_WINDOW_US) {
    log_debug("  [MDBG] %s crashed %us after kstuff pause; autotune skipped%s%s",
              g_mdbg.game.title_id, (unsigned)(post_pause_us / 1000000ull),
              reason ? ": " : "", reason ? reason : "");
    notify_system_info("App crashed after KStuff pause: %s. Autotune skipped.",
                       g_mdbg.game.title_id);
    clear_tracked_game();
    return;
  }

  char reason_summary[128];
  summarize_failure_reason(reason, reason_summary, sizeof(reason_summary));

  uint32_t tuned_delay_seconds = 0;
  if (upsert_kstuff_autotune_pause_delay(g_mdbg.game.title_id,
                                         g_mdbg.game.pause_delay_seconds,
                                         &tuned_delay_seconds)) {
    log_debug("  [MDBG] autotune pause delay updated: %s=%us",
              g_mdbg.game.title_id, tuned_delay_seconds);
    if (reason_summary[0] != '\0')
      log_debug("  [MDBG] autotune trigger: %s", reason_summary);
    if (reason_is_rtld_error(reason)) {
      notify_system_info("%s: %s. Delay increased to %us.",
                         g_mdbg.game.title_id,
                         reason_summary[0] != '\0' ? reason_summary
                                                   : "Can't load module after "
                                                     "KStuff pause",
                         tuned_delay_seconds);
    } else {
      notify_system_info("Crash detected after KStuff pause: pause delay for %s "
                         "increased to %us. Launch the game again.",
                         g_mdbg.game.title_id, tuned_delay_seconds);
    }
    clear_tracked_game();
    return;
  }

  log_debug("  [MDBG] failed to persist autotune pause delay for %s%s%s",
            g_mdbg.game.title_id, reason ? ": " : "", reason ? reason : "");
  notify_system_info("Crash detected after KStuff pause: %s. Failed to update "
                     "autotune delay.",
                     g_mdbg.game.title_id);
  clear_tracked_game();
}

static void process_klog_line(const char *line, uint64_t now_us) {
  if (!klog_line_matches_tracked_load_error(line))
    return;

  log_debug("  [MDBG] klog load error for %s: %s", g_mdbg.game.title_id, line);
  handle_post_pause_failure(line, now_us);
}

static void append_klog_char(char ch, uint64_t now_us) {
  if (!g_mdbg.game.active)
    return;

  if (ch == '\r' || ch == '\n') {
    if (g_mdbg.klog_line_length == 0)
      return;
    g_mdbg.klog_line[g_mdbg.klog_line_length] = '\0';
    process_klog_line(g_mdbg.klog_line, now_us);
    reset_klog_buffer();
    return;
  }

  if (g_mdbg.klog_line_length + 1u >= sizeof(g_mdbg.klog_line)) {
    g_mdbg.klog_line[g_mdbg.klog_line_length] = '\0';
    process_klog_line(g_mdbg.klog_line, now_us);
    reset_klog_buffer();
  }

  g_mdbg.klog_line[g_mdbg.klog_line_length++] = ch;
}

static void drain_klog_monitor(void) {
  if (g_mdbg.klog_fd < 0)
    return;

  char chunk[KLOG_POLL_CHUNK_SIZE];
  for (;;) {
    ssize_t read_size = read(g_mdbg.klog_fd, chunk, sizeof(chunk));
    if (read_size <= 0) {
      if (read_size < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        log_debug("  [MDBG] /dev/klog initial drain failed for %s: %s",
                  g_mdbg.game.title_id, strerror(errno));
        g_mdbg.game.klog_monitoring_active = false;
      }
      break;
    }
  }

  reset_klog_buffer();
}

static void poll_klog_monitor(uint64_t now_us) {
  if (!g_mdbg.game.active || !g_mdbg.game.klog_monitoring_active) {
    return;
  }

  if (!open_klog_device())
    return;

  char chunk[KLOG_POLL_CHUNK_SIZE];
  for (;;) {
    ssize_t read_size = read(g_mdbg.klog_fd, chunk, sizeof(chunk));
    if (read_size == 0)
      return;
    if (read_size < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;

      log_debug("  [MDBG] /dev/klog read failed for %s: %s",
                g_mdbg.game.title_id, strerror(errno));
      g_mdbg.game.klog_monitoring_active = false;
      reset_klog_buffer();
      return;
    }

    for (ssize_t i = 0; i < read_size; ++i) {
      append_klog_char(chunk[i], now_us);
      if (!g_mdbg.game.active)
        return;
    }
  }
}

static void start_klog_monitoring(void) {
  if (!g_mdbg.game.active)
    return;

  g_mdbg.game.klog_monitoring_active = true;
  if (!open_klog_device())
    return;
  drain_klog_monitor();
}

static void handle_crash_candidate(uint64_t flags, uint32_t state_flags,
                                   uint32_t stop_reason, uint64_t now_us) {
  if (!g_mdbg.game.active)
    return;

  const char *comm = g_mdbg.game.comm[0] != '\0' ? g_mdbg.game.comm : "?";
  log_debug("  [MDBG] crash-candidate: %s pid=%ld comm=%s flags=0x%08" PRIx64
            " stateFlags=0x%02" PRIx32 " stopReason=0x%08" PRIx32,
            g_mdbg.game.title_id, (long)g_mdbg.game.pid, comm, flags,
            state_flags, stop_reason);

  if (!g_mdbg.game.pause_seen || g_mdbg.game.pause_time_us == 0 ||
      now_us < g_mdbg.game.pause_time_us) {
    handle_pre_pause_failure("crash-candidate");
    return;
  }

  handle_post_pause_failure("crash-candidate", now_us);
}

void sm_mdbg_init(void) {
  memset(&g_mdbg, 0, sizeof(g_mdbg));
  g_mdbg.klog_fd = -1;
  reset_tracked_game(&g_mdbg.game);
  reset_klog_buffer();
}

void sm_mdbg_shutdown(void) {
  clear_tracked_game();
  close_klog_device();
  g_mdbg.privilege_probe_done = false;
  g_mdbg.privilege_ready = false;
}

void sm_mdbg_game_on_exec(pid_t pid, const char *title_id, uint32_t app_id) {
  if (pid <= 0 || !title_id || title_id[0] == '\0')
    return;
  if (!sm_mdbg_enabled()) {
    clear_tracked_game();
    return;
  }

  if (g_mdbg.game.active && g_mdbg.game.pid != pid) {
    log_debug("  [MDBG] replacing tracked game pid=%ld (%s) with pid=%ld (%s)",
              (long)g_mdbg.game.pid, g_mdbg.game.title_id, (long)pid, title_id);
  }

  clear_tracked_game();

  uint64_t now_us = monotonic_time_us();
  g_mdbg.game.active = true;
  g_mdbg.game.pid = pid;
  g_mdbg.game.next_poll_us = now_us;
  (void)strlcpy(g_mdbg.game.title_id, title_id, sizeof(g_mdbg.game.title_id));

  struct kinfo_proc ki;
  if (read_proc_info(pid, &ki))
    capture_process_comm(&ki);

  log_debug("  [MDBG] tracking crash-candidate state: %s pid=%ld app_id=0x%08X",
            g_mdbg.game.title_id, (long)pid, app_id);
}

void sm_mdbg_game_on_kstuff_pause(pid_t pid, uint64_t pause_time_us,
                                  uint32_t pause_delay_seconds) {
  if (!g_mdbg.game.active || g_mdbg.game.pid != pid)
    return;

  g_mdbg.game.pause_seen = true;
  g_mdbg.game.pause_time_us = pause_time_us;
  g_mdbg.game.monitor_deadline_us =
      g_mdbg.game.pause_time_us + MDBG_AUTOTUNE_WINDOW_US;
  g_mdbg.game.pause_delay_seconds = pause_delay_seconds;
  g_mdbg.game.next_poll_us = pause_time_us;
  start_klog_monitoring();
}

void sm_mdbg_game_on_exit(pid_t pid) {
  if (!g_mdbg.game.active || g_mdbg.game.pid != pid)
    return;

  clear_tracked_game();
}

void sm_mdbg_game_shutdown(void) {
  clear_tracked_game();
}

uint64_t sm_mdbg_next_wake_us(uint64_t now_us) {
  (void)now_us;
  if (!sm_mdbg_enabled())
    return 0;
  if (!g_mdbg.game.active)
    return 0;

  uint64_t next_wake_us = g_mdbg.game.next_poll_us;
  if (g_mdbg.game.monitor_deadline_us != 0 &&
      (next_wake_us == 0 || g_mdbg.game.monitor_deadline_us < next_wake_us)) {
    next_wake_us = g_mdbg.game.monitor_deadline_us;
  }
  return next_wake_us;
}

void sm_mdbg_poll(void) {
  if (!sm_mdbg_enabled())
    return;
  if (!g_mdbg.game.active)
    return;

  uint64_t now_us = monotonic_time_us();
  if (now_us < g_mdbg.game.next_poll_us) {
    return;
  }
  if (g_mdbg.game.pause_seen && g_mdbg.game.monitor_deadline_us != 0 &&
      now_us >= g_mdbg.game.monitor_deadline_us) {
    log_debug("  [MDBG] crash monitoring window expired for %s pid=%ld",
              g_mdbg.game.title_id, (long)g_mdbg.game.pid);
    clear_tracked_game();
    return;
  }

  poll_klog_monitor(now_us);
  if (!g_mdbg.game.active)
    return;

  g_mdbg.game.next_poll_us = now_us + GAME_LIFECYCLE_POLL_INTERVAL_US;

  if (!ensure_mdbg_privileges()) {
    if (!g_mdbg.game.klog_monitoring_active)
      g_mdbg.game.next_poll_us = 0;
    return;
  }

  uint64_t flags = 0;
  int ret = query_mdbg_flags(g_mdbg.game.pid, &flags);
  if (is_mdbg_process_gone_error(ret)) {
    clear_tracked_game();
    return;
  }
  if (ret != 0)
    return;

  if ((flags & MDBG_FLAG_EXCEPTION_STOP) == 0)
    return;

  uint32_t state_flags = 0;
  uint32_t stop_reason = 0;
  ret = query_mdbg_state3(g_mdbg.game.pid, &state_flags, &stop_reason);
  if (is_mdbg_process_gone_error(ret)) {
    clear_tracked_game();
    return;
  }
  if (ret != 0) {
    state_flags = 0;
    stop_reason = 0;
  }

  handle_crash_candidate(flags, state_flags, stop_reason, now_us);
}
