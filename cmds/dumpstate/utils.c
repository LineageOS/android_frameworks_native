/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/klog.h>
#include <time.h>
#include <unistd.h>

#include <cutils/debugger.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include "dumpstate.h"

/* list of native processes to include in the native dumps */
static const char* native_processes_to_dump[] = {
        "/system/bin/drmserver",
        "/system/bin/mediaserver",
        "/system/bin/sdcard",
        "/system/bin/surfaceflinger",
        NULL,
};

void for_each_pid(void (*func)(int, const char *), const char *header) {
    DIR *d;
    struct dirent *de;

    if (!(d = opendir("/proc"))) {
        printf("Failed to open /proc (%s)\n", strerror(errno));
        return;
    }

    printf("\n------ %s ------\n", header);
    while ((de = readdir(d))) {
        int pid;
        int fd;
        char cmdpath[255];
        char cmdline[255];

        if (!(pid = atoi(de->d_name))) {
            continue;
        }

        sprintf(cmdpath,"/proc/%d/cmdline", pid);
        memset(cmdline, 0, sizeof(cmdline));
        if ((fd = open(cmdpath, O_RDONLY)) < 0) {
            strcpy(cmdline, "N/A");
        } else {
            read(fd, cmdline, sizeof(cmdline));
            close(fd);
        }
        func(pid, cmdline);
    }

    closedir(d);
}

void show_wchan(int pid, const char *name) {
    char path[255];
    char buffer[255];
    int fd;

    memset(buffer, 0, sizeof(buffer));

    sprintf(path, "/proc/%d/wchan", pid);
    if ((fd = open(path, O_RDONLY)) < 0) {
        printf("Failed to open '%s' (%s)\n", path, strerror(errno));
        return;
    }

    if (read(fd, buffer, sizeof(buffer)) < 0) {
        printf("Failed to read '%s' (%s)\n", path, strerror(errno));
        goto out_close;
    }

    printf("%-7d %-32s %s\n", pid, name, buffer);

out_close:
    close(fd);
    return;
}

void do_dmesg() {
    printf("------ KERNEL LOG (dmesg) ------\n");
    /* Get size of kernel buffer */
    int size = klogctl(KLOG_SIZE_BUFFER, NULL, 0);
    if (size <= 0) {
        printf("Unexpected klogctl return value: %d\n\n", size);
        return;
    }
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL) {
        printf("memory allocation failed\n\n");
        return;
    }
    int retval = klogctl(KLOG_READ_ALL, buf, size);
    if (retval < 0) {
        printf("klogctl failure\n\n");
        free(buf);
        return;
    }
    buf[retval] = '\0';
    printf("%s\n\n", buf);
    free(buf);
    return;
}

void do_showmap(int pid, const char *name) {
    static bool ran = false, skip = false;
    char title[255];
    char arg[255];

    sprintf(title, "SHOW MAP %d (%s)", pid, name);
    sprintf(arg, "%d", pid);

    if (skip) {
        /* Skip due to non-zero exit status on first run. */
        printf("------ %s: Skipped. ------\n", title);
    } else {
        int status = run_command(title, 10, SU_PATH, "root", "showmap", arg, NULL);
        if (!ran) {
            ran  = true;
            skip = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
        }
    }
}

/* prints the contents of a file */
int dump_file(const char *title, const char* path) {
    char buffer[32768];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int err = errno;
        if (title) printf("------ %s (%s) ------\n", title, path);
        printf("*** %s: %s\n", path, strerror(err));
        if (title) printf("\n");
        return -1;
    }

    if (title) printf("------ %s (%s", title, path);

    if (title) {
        struct stat st;
        if (memcmp(path, "/proc/", 6) && memcmp(path, "/sys/", 5) && !fstat(fd, &st)) {
            char stamp[80];
            time_t mtime = st.st_mtime;
            strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", localtime(&mtime));
            printf(": %s", stamp);
        }
        printf(") ------\n");
    }

    int newline = 0;
    for (;;) {
        int ret = read(fd, buffer, sizeof(buffer));
        if (ret > 0) {
            newline = (buffer[ret - 1] == '\n');
            ret = fwrite(buffer, ret, 1, stdout);
        }
        if (ret <= 0) break;
    }

    close(fd);
    if (!newline) printf("\n");
    if (title) printf("\n");
    return 0;
}

/* forks a command and waits for it to finish */
int run_command(const char *title, int timeout_seconds, const char *command, ...) {
    fflush(stdout);
    clock_t start = clock();
    pid_t pid = fork();

    /* handle error case */
    if (pid < 0) {
        printf("*** fork: %s\n", strerror(errno));
        return pid;
    }

    /* handle child case */
    if (pid == 0) {
        const char *args[1024] = {command};
        size_t arg = 1;
        char sucmd[255];
        bool su = false;

        if (strcmp(command, SU_PATH) == 0) {
            /* Need to transform calls to su from:
             *   su LOGIN COMMAND ...
             * to:
             *   su -c 'COMMAND "$@"' -- LOGIN COMMAND ... */
            args[arg++] = "-c";
            args[arg++] = sucmd;
            args[arg++] = "--";
            sucmd[0] = '\0';
            su = true;
        }

        va_list ap;
        va_start(ap, command);
        if (title) printf("------ %s (%s", title, command);
        for (; arg < sizeof(args) / sizeof(args[0]); ++arg) {
            args[arg] = va_arg(ap, const char *);
            if (args[arg] == NULL) break;
            if (su && arg == 5) snprintf(sucmd, sizeof(sucmd), "%s \"$@\"", args[arg]);
            if (title) printf(" %s", args[arg]);
        }
        if (title) printf(") ------\n");
        fflush(stdout);

        execvp(command, (char**) args);
        printf("*** exec(%s): %s\n", command, strerror(errno));
        fflush(stdout);
        _exit(-1);
    }

    /* handle parent case */
    for (;;) {
        int status;
        pid_t p = waitpid(pid, &status, WNOHANG);
        float elapsed = (float) (clock() - start) / CLOCKS_PER_SEC;
        if (p == pid) {
            if (WIFSIGNALED(status)) {
                printf("*** %s: Killed by signal %d\n", command, WTERMSIG(status));
            } else if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
                printf("*** %s: Exit code %d\n", command, WEXITSTATUS(status));
            }
            if (title) printf("[%s: %.1fs elapsed]\n\n", command, elapsed);
            return status;
        }

        if (timeout_seconds && elapsed > timeout_seconds) {
            printf("*** %s: Timed out after %.1fs (killing pid %d)\n", command, elapsed, pid);
            kill(pid, SIGTERM);
            return -1;
        }

        usleep(100000);  // poll every 0.1 sec
    }
}

size_t num_props = 0;
static char* props[2000];

static void print_prop(const char *key, const char *name, void *user) {
    (void) user;
    if (num_props < sizeof(props) / sizeof(props[0])) {
        char buf[PROPERTY_KEY_MAX + PROPERTY_VALUE_MAX + 10];
        snprintf(buf, sizeof(buf), "[%s]: [%s]\n", key, name);
        props[num_props++] = strdup(buf);
    }
}

static int compare_prop(const void *a, const void *b) {
    return strcmp(*(char * const *) a, *(char * const *) b);
}

/* prints all the system properties */
void print_properties() {
    size_t i;
    num_props = 0;
    property_list(print_prop, NULL);
    qsort(&props, num_props, sizeof(props[0]), compare_prop);

    printf("------ SYSTEM PROPERTIES ------\n");
    for (i = 0; i < num_props; ++i) {
        fputs(props[i], stdout);
        free(props[i]);
    }
    printf("\n");
}

/* redirect output to a service control socket */
void redirect_to_socket(FILE *redirect, const char *service) {
    int s = android_get_control_socket(service);
    if (s < 0) {
        fprintf(stderr, "android_get_control_socket(%s): %s\n", service, strerror(errno));
        exit(1);
    }
    if (listen(s, 4) < 0) {
        fprintf(stderr, "listen(control socket): %s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr addr;
    socklen_t alen = sizeof(addr);
    int fd = accept(s, &addr, &alen);
    if (fd < 0) {
        fprintf(stderr, "accept(control socket): %s\n", strerror(errno));
        exit(1);
    }

    fflush(redirect);
    dup2(fd, fileno(redirect));
    close(fd);
}

/* redirect output to a file, optionally gzipping; returns gzip pid (or -1) */
pid_t redirect_to_file(FILE *redirect, char *path, int gzip_level) {
    char *chp = path;

    /* skip initial slash */
    if (chp[0] == '/')
        chp++;

    /* create leading directories, if necessary */
    while (chp && chp[0]) {
        chp = strchr(chp, '/');
        if (chp) {
            *chp = 0;
            mkdir(path, 0775);  /* drwxrwxr-x */
            *chp++ = '/';
        }
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        exit(1);
    }

    pid_t gzip_pid = -1;
    if (gzip_level > 0) {
        int fds[2];
        if (pipe(fds)) {
            fprintf(stderr, "pipe: %s\n", strerror(errno));
            exit(1);
        }

        fflush(redirect);
        fflush(stdout);

        gzip_pid = fork();
        if (gzip_pid < 0) {
            fprintf(stderr, "fork: %s\n", strerror(errno));
            exit(1);
        }

        if (gzip_pid == 0) {
            dup2(fds[0], STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);

            close(fd);
            close(fds[0]);
            close(fds[1]);

            char level[10];
            snprintf(level, sizeof(level), "-%d", gzip_level);
            execlp("gzip", "gzip", level, NULL);
            fprintf(stderr, "exec(gzip): %s\n", strerror(errno));
            _exit(-1);
        }

        close(fd);
        close(fds[0]);
        fd = fds[1];
    }

    dup2(fd, fileno(redirect));
    close(fd);
    return gzip_pid;
}

static bool should_dump_native_traces(const char* path) {
    for (const char** p = native_processes_to_dump; *p; p++) {
        if (!strcmp(*p, path)) {
            return true;
        }
    }
    return false;
}

/* dump Dalvik and native stack traces, return the trace file location (NULL if none) */
const char *dump_traces() {
    const char* result = NULL;

    char traces_path[PROPERTY_VALUE_MAX] = "";
    property_get("dalvik.vm.stack-trace-file", traces_path, "");
    if (!traces_path[0]) return NULL;

    /* move the old traces.txt (if any) out of the way temporarily */
    char anr_traces_path[PATH_MAX];
    strlcpy(anr_traces_path, traces_path, sizeof(anr_traces_path));
    strlcat(anr_traces_path, ".anr", sizeof(anr_traces_path));
    if (rename(traces_path, anr_traces_path) && errno != ENOENT) {
        fprintf(stderr, "rename(%s, %s): %s\n", traces_path, anr_traces_path, strerror(errno));
        return NULL;  // Can't rename old traces.txt -- no permission? -- leave it alone instead
    }

    /* make the directory if necessary */
    char anr_traces_dir[PATH_MAX];
    strlcpy(anr_traces_dir, traces_path, sizeof(anr_traces_dir));
    char *slash = strrchr(anr_traces_dir, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (!mkdir(anr_traces_dir, 0775)) {
            chown(anr_traces_dir, AID_SYSTEM, AID_SYSTEM);
            chmod(anr_traces_dir, 0775);
        } else if (errno != EEXIST) {
            fprintf(stderr, "mkdir(%s): %s\n", anr_traces_dir, strerror(errno));
            return NULL;
        }
    }

    /* create a new, empty traces.txt file to receive stack dumps */
    int fd = open(traces_path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0666);  /* -rw-rw-rw- */
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", traces_path, strerror(errno));
        return NULL;
    }
    int chmod_ret = fchmod(fd, 0666);
    if (chmod_ret < 0) {
        fprintf(stderr, "fchmod on %s failed: %s\n", traces_path, strerror(errno));
        close(fd);
        return NULL;
    }

    /* walk /proc and kill -QUIT all Dalvik processes */
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        fprintf(stderr, "/proc: %s\n", strerror(errno));
        goto error_close_fd;
    }

    /* use inotify to find when processes are done dumping */
    int ifd = inotify_init();
    if (ifd < 0) {
        fprintf(stderr, "inotify_init: %s\n", strerror(errno));
        goto error_close_fd;
    }

    int wfd = inotify_add_watch(ifd, traces_path, IN_CLOSE_WRITE);
    if (wfd < 0) {
        fprintf(stderr, "inotify_add_watch(%s): %s\n", traces_path, strerror(errno));
        goto error_close_ifd;
    }

    struct dirent *d;
    int dalvik_found = 0;
    while ((d = readdir(proc))) {
        int pid = atoi(d->d_name);
        if (pid <= 0) continue;

        char path[PATH_MAX];
        char data[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        ssize_t len = readlink(path, data, sizeof(data) - 1);
        if (len <= 0) {
            continue;
        }
        data[len] = '\0';

        if (!strcmp(data, "/system/bin/app_process")) {
            /* skip zygote -- it won't dump its stack anyway */
            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            int fd = open(path, O_RDONLY);
            len = read(fd, data, sizeof(data) - 1);
            close(fd);
            if (len <= 0) {
                continue;
            }
            data[len] = '\0';
            if (!strcmp(data, "zygote")) {
                continue;
            }

            ++dalvik_found;
            if (kill(pid, SIGQUIT)) {
                fprintf(stderr, "kill(%d, SIGQUIT): %s\n", pid, strerror(errno));
                continue;
            }

            /* wait for the writable-close notification from inotify */
            struct pollfd pfd = { ifd, POLLIN, 0 };
            int ret = poll(&pfd, 1, 200);  /* 200 msec timeout */
            if (ret < 0) {
                fprintf(stderr, "poll: %s\n", strerror(errno));
            } else if (ret == 0) {
                fprintf(stderr, "warning: timed out dumping pid %d\n", pid);
            } else {
                struct inotify_event ie;
                read(ifd, &ie, sizeof(ie));
            }
        } else if (should_dump_native_traces(data)) {
            /* dump native process if appropriate */
            if (lseek(fd, 0, SEEK_END) < 0) {
                fprintf(stderr, "lseek: %s\n", strerror(errno));
            } else {
                dump_backtrace_to_file(pid, fd);
            }
        }
    }

    if (dalvik_found == 0) {
        fprintf(stderr, "Warning: no Dalvik processes found to dump stacks\n");
    }

    static char dump_traces_path[PATH_MAX];
    strlcpy(dump_traces_path, traces_path, sizeof(dump_traces_path));
    strlcat(dump_traces_path, ".bugreport", sizeof(dump_traces_path));
    if (rename(traces_path, dump_traces_path)) {
        fprintf(stderr, "rename(%s, %s): %s\n", traces_path, dump_traces_path, strerror(errno));
        goto error_close_ifd;
    }
    result = dump_traces_path;

    /* replace the saved [ANR] traces.txt file */
    rename(anr_traces_path, traces_path);

error_close_ifd:
    close(ifd);
error_close_fd:
    close(fd);
    return result;
}

void play_sound(const char* path) {
    run_command(NULL, 5, "/system/bin/stagefright", "-o", "-a", path, NULL);
}
