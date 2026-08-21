#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    CONTROL_PORT = 8080,
    SUPERVISOR_UID = 1001,
    SUPERVISOR_GID = 1001,
};

static void fail(const char *operation) {
    fprintf(stderr, "aex-control-listener: %s: %s\n", operation, strerror(errno));
    exit(111);
}

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "aex-control-listener: %s\n", message);
        exit(111);
    }
}

int main(int argc, char **argv) {
    require(argc == 2, "expected the Hand supervisor executable");

    const char *configured = getenv("HAND_LISTEN");
    require(configured != NULL && strcmp(configured, "0.0.0.0:8080") == 0,
            "HAND_LISTEN must be the sealed provider endpoint");

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        fail("socket");
    }
    int enabled = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0) {
        fail("setsockopt");
    }
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(CONTROL_PORT),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        fail("bind");
    }
    if (listen(listener, SOMAXCONN) < 0) {
        fail("listen");
    }
    /*
     * The provider may already own descriptor 3. Preserve every inherited descriptor and pass the
     * actual new listener number to the supervisor instead of replacing a provider control fd.
     */
    if (listener < 3) {
        int replacement = fcntl(listener, F_DUPFD, 3);
        if (replacement < 0) {
            fail("fcntl(F_DUPFD)");
        }
        close(listener);
        listener = replacement;
    }
    int descriptor_flags = fcntl(listener, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(listener, F_SETFD, descriptor_flags & ~FD_CLOEXEC) < 0) {
        fail("fcntl");
    }
    char listener_number[32];
    int listener_number_bytes =
        snprintf(listener_number, sizeof(listener_number), "%d", listener);
    require(listener_number_bytes > 0 &&
                (size_t)listener_number_bytes < sizeof(listener_number),
            "could not encode the control listener descriptor");
    fprintf(stderr, "aex-control-listener: reserved port %d on descriptor %d\n",
            CONTROL_PORT, listener);

    struct passwd *supervisor = getpwnam("hand");
    require(supervisor != NULL, "Hand supervisor account is unavailable");
    require(supervisor->pw_uid == SUPERVISOR_UID && supervisor->pw_gid == SUPERVISOR_GID,
            "Hand supervisor identity does not match the sealed image");
    if (initgroups("hand", supervisor->pw_gid) < 0) {
        fail("initgroups");
    }
    if (setgid(supervisor->pw_gid) < 0) {
        fail("setgid");
    }
    if (setuid(supervisor->pw_uid) < 0) {
        fail("setuid");
    }
    require(geteuid() == SUPERVISOR_UID && getegid() == SUPERVISOR_GID,
            "failed to enter the Hand supervisor identity");

    if (setenv("HOME", "/home/agent", 1) < 0 || setenv("USER", "hand", 1) < 0 ||
        setenv("LOGNAME", "hand", 1) < 0 ||
        setenv("HAND_LISTEN_FD", listener_number, 1) < 0) {
        fail("setenv");
    }
    char *const child_argv[] = {argv[1], NULL};
    execv(argv[1], child_argv);
    fail("execv");
}
