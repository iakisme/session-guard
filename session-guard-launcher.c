/*
 * session-guard-launcher
 *
 * Tiny launchd job root for session-guard. Its only job is to be the process
 * that TCC evaluates for Full Disk Access: Endpoint Security clients (eslogger)
 * require the *responsible* process to hold FDA, and for a LaunchDaemon that is
 * the job's own executable. Granting FDA to /bin/sh or /usr/bin/python3 would
 * hand it to every launchd job using those interpreters; granting it to this
 * dedicated binary scopes it to exactly one daemon.
 *
 * Usage:
 *   session-guard-launcher PRODUCER [ARGS...] -- CONSUMER [ARGS...]
 *
 * Spawns PRODUCER with stdout piped into CONSUMER's stdin, then waits. When
 * either side exits, the other is terminated and the launcher exits non-zero so
 * launchd (KeepAlive) restarts the pair.
 *
 * Build:  cc -O2 -Wall -o session-guard-launcher session-guard-launcher.c
 *         codesign -s - -i io.github.iakisme.session-guard -f session-guard-launcher
 */
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static pid_t producer = 0, consumer = 0;

static void forward_term(int sig) {
    if (producer > 0) kill(producer, sig);
    if (consumer > 0) kill(consumer, sig);
}

static pid_t spawn_with(char **argv, int stdin_fd, int stdout_fd, int close_a, int close_b) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (stdin_fd >= 0) posix_spawn_file_actions_adddup2(&fa, stdin_fd, STDIN_FILENO);
    if (stdout_fd >= 0) posix_spawn_file_actions_adddup2(&fa, stdout_fd, STDOUT_FILENO);
    if (close_a >= 0) posix_spawn_file_actions_addclose(&fa, close_a);
    if (close_b >= 0) posix_spawn_file_actions_addclose(&fa, close_b);
    pid_t pid;
    int rc = posix_spawn(&pid, argv[0], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) {
        fprintf(stderr, "session-guard-launcher: spawn %s: %s\n", argv[0], strerror(rc));
        return -1;
    }
    return pid;
}

int main(int argc, char **argv) {
    int sep = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep = i; break; }
    }
    if (sep < 2 || sep == argc - 1) {
        fprintf(stderr, "usage: %s PRODUCER [ARGS...] -- CONSUMER [ARGS...]\n", argv[0]);
        return 64;
    }
    argv[sep] = NULL;
    char **prod_argv = &argv[1];
    char **cons_argv = &argv[sep + 1];

    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return 1; }

    producer = spawn_with(prod_argv, -1, pfd[1], pfd[0], pfd[1]);
    if (producer < 0) return 1;
    consumer = spawn_with(cons_argv, pfd[0], -1, pfd[0], pfd[1]);
    if (consumer < 0) { kill(producer, SIGTERM); return 1; }
    close(pfd[0]);
    close(pfd[1]);

    signal(SIGTERM, forward_term);
    signal(SIGINT, forward_term);
    signal(SIGHUP, forward_term);

    int status = 0;
    pid_t done = waitpid(-1, &status, 0);
    while (done < 0 && errno == EINTR) done = waitpid(-1, &status, 0);

    const char *who = done == producer ? "producer" : (done == consumer ? "consumer" : "unknown");
    fprintf(stderr, "session-guard-launcher: %s (pid %d) exited status=%d signal=%d; stopping the other\n",
            who, (int)done, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
            WIFSIGNALED(status) ? WTERMSIG(status) : 0);

    pid_t other = done == producer ? consumer : producer;
    if (other > 0) {
        kill(other, SIGTERM);
        for (int i = 0; i < 50; i++) {        /* up to ~5s for a clean exit */
            if (waitpid(other, NULL, WNOHANG) == other) { other = 0; break; }
            usleep(100 * 1000);
        }
        if (other > 0) { kill(other, SIGKILL); waitpid(other, NULL, 0); }
    }
    return 1;  /* non-zero so launchd KeepAlive restarts us */
}
