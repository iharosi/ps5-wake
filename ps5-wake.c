// PlayStation 5 Discovery and Wake-up Utility
// Original ps4-wake code by Darryl Sokoloski <darryl@sokoloski.ca>
// PS5 code changes by Gergely Iharosi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "sha1.h"

#define _VERSION            "1.0"
#define _DST_PORT           9302
#define _PROBES             3

#define _DDP_VERSION        "00030010"
#define _DDP_CLIENTTYPE     "vr"
#define _DDP_AUTHTYPE       "R"
#define _DDP_MODEL          "m"
#define _DDP_APPTYPE        "r"

#define _EXIT_SUCCESS       0
#define _EXIT_BADOPTION     1
#define _EXIT_NOUSERCRED    2
#define _EXIT_SOCKET        3
#define _EXIT_NOHOSTADDR    4
#define _EXIT_BADHOSTADDR   5
#define _EXIT_DEVNOTFOUND   6
#define _EXIT_HOSTNOTFOUND  7

struct ddp_reply
{
    short code;
    char *host_id;
    char *host_name;
    char *host_type;
    char *running_app_name;
    char *running_app_titleid;
    char *version;
    short host_request_port;
};

static char *buffer = NULL, *iface = NULL;
static char *pkt_input, *pkt_output, *json_buffer;
static char *host_remote = NULL, *cred = NULL;
static int rc, broadcast = 0, probe = 0, json = 0, verbose = 0, probes = _PROBES;
static int sd = -1;
static short port_local = INADDR_ANY, port_remote = _DST_PORT;
static struct ddp_reply *reply = NULL;

static int ddp_parse(char *buffer, struct ddp_reply *reply)
{
    char *c, *sp1, *sp2;
    char *p = buffer, *token = NULL, *key, *value;

    for (p = buffer; ; p = NULL) {
        token = strtok_r(p, "\n", &sp1);
        if (token == NULL) break;

        if (token[0] == 'H' && token[1] == 'T' &&
            token[2] == 'T' && token[3] == 'P') {
            for (p = token + 8; *p == ' '; p++);
            for (c = p; isdigit(*p); p++);
            *p = '\0'; reply->code = (short)atoi(c);
            continue;
        }

        p = token;
        key = strtok_r(p, ":", &sp2);
        if (key == NULL) continue;

        p = NULL;
        value = strtok_r(p, ":", &sp2);
        if (value == NULL) continue;

        if (!strcmp(key, "host-id"))
            reply->host_id = strdup(value);
        else if (!strcmp(key, "host-type"))
            reply->host_type = strdup(value);
        else if (!strcmp(key, "host-name"))
            reply->host_name = strdup(value);
        else if (!strcmp(key, "host-request-port"))
            reply->host_request_port = (short)atoi(value);
        else if (!strcmp(key, "running-app-name"))
            reply->running_app_name = strdup(value);
        else if (!strcmp(key, "running-app-titleid"))
            reply->running_app_titleid = strdup(value);
    }

    if (reply->code == 0) return 1;

    return 0;
}

static void ddp_free(struct ddp_reply *reply)
{
    if (reply == NULL) return;
    if (reply->host_id != NULL) free(reply->host_id);
    if (reply->host_name != NULL) free(reply->host_name);
    if (reply->host_type != NULL) free(reply->host_type);
    if (reply->running_app_name != NULL) free(reply->running_app_name);
    if (reply->running_app_titleid != NULL) free(reply->running_app_titleid);
    if (reply->version != NULL) free(reply->version);
}

static int iface_get_bcast_addr(const char *iface, struct sockaddr_in *sa)
{
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "Error getting interface addresses: %s\n", strerror(errno));
        return 1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, iface)) continue;

        memcpy(&sa->sin_addr,
            &((struct sockaddr_in *)ifa->ifa_dstaddr)->sin_addr,
            sizeof(struct in_addr));

        break;
    }

    freeifaddrs(ifaddr);

    return 0;
}

static void json_output(struct ddp_reply *reply)
{
    char *p = json_buffer;

    const char *host_id = p, *host_name = p, *host_type = p;
    const char *running_app_name = p, *running_app_titleid = p;
    const char *version = p;

    sprintf(p, "null");
    p += strlen(json_buffer) + 1;

    if (reply->host_id != NULL) {
        host_id = p;
        sprintf(p, "\"%s\"", reply->host_id);
        p += strlen(p) + 1;
    }
    if (reply->host_name != NULL) {
        host_name = p;
        sprintf(p, "\"%s\"", reply->host_name);
        p += strlen(p) + 1;
    }
    if (reply->host_type != NULL) {
        host_type = p;
        sprintf(p, "\"%s\"", reply->host_type);
        p += strlen(p) + 1;
    }
    if (reply->running_app_name != NULL) {
        running_app_name = p;
        sprintf(p, "\"%s\"", reply->running_app_name);
        p += strlen(p) + 1;
    }
    if (reply->running_app_titleid != NULL) {
        running_app_titleid = p;
        sprintf(p, "\"%s\"", reply->running_app_titleid);
        p += strlen(p) + 1;
    }
    if (reply->version != NULL) {
        version = p;
        sprintf(p, "\"%s\"", reply->version);
        p += strlen(p) + 1;
    }

    memcpy(p, &reply->code, sizeof(short));
    p += sizeof(short);
    memcpy(p, &reply->host_request_port, sizeof(short));
    p += sizeof(short);

    sha1 sha1_ctx;
    sha1_init(&sha1_ctx);
    sha1_write(&sha1_ctx, json_buffer, (size_t)(p - json_buffer));

    uint8_t *sha1_binary = sha1_result(&sha1_ctx);

    char sha1_fingerprint[SHA1_HASH_LENGTH * 2 + 1];
    p = sha1_fingerprint;

    for (int i = 0; i < SHA1_HASH_LENGTH; i++, p += 2)
        sprintf(p, "%02x", sha1_binary[i]);

    fprintf(stdout,
        "{\"code\":%hd,\"host_id\":%s,\"host_name\":%s,\"host_type\":%s,"
        "\"running_app_name\":%s,\"running_app_titleid\":%s,"
        "\"version\":%s,\"host_request_port\":%hd,\"timestamp\":%ld,"
        "\"fingerprint\":\"%s\"}\n",
        reply->code, host_id, host_name, host_type,
        running_app_name, running_app_titleid,
        version, reply->host_request_port, (long)time(NULL),
        sha1_fingerprint
    );
}

void onexit(void)
{
    if (host_remote != NULL) free(host_remote);
    if (cred != NULL) free(cred);
    if (sd > -1) close(sd);
    if (buffer != NULL) free(buffer);
    if (iface != NULL) free(iface);
    if (reply != NULL) {
        ddp_free(reply);
        free(reply);
    }
}

static void usage(int rc)
{
    fprintf(stderr, "ps5-wake v%s Help\n", _VERSION);
    fprintf(stderr, " Probe:\n");
    fprintf(stderr, "  -P, --probe\n    Probe network for devices.\n");
    fprintf(stderr, " Wake:\n");
    fprintf(stderr, "  -W, --wake <user-credential>\n    Wake device using specified user credential.\n");
    fprintf(stderr, " Options:\n");
    fprintf(stderr, "  -B, --broadcast\n    Send broadcasts.\n");
    fprintf(stderr, "  -L, --local-port <port address>\n    Specifiy a local port address.\n");
    fprintf(stderr, "  -H, --remote-host <host address>\n    Specifiy a remote host address.\n");
    fprintf(stderr, "  -R, --remote-port <port address>\n    Specifiy a remote port address (default: %d).\n", _DST_PORT);
    fprintf(stderr, "  -I, --interface <interface>\n    Bind to interface.\n");
    fprintf(stderr, "  -j, --json\n    Output JSON.\n");
    fprintf(stderr, "  -v, --verbose\n    Enable verbose messages.\n");

    exit(rc);
}

int main(int argc, char *argv[])
{
    atexit(onexit);

    long page_size = getpagesize();
    long buffer_size = page_size * 3;

    buffer = malloc(buffer_size);
    memset(buffer, 0, buffer_size);

    pkt_input = buffer;
    pkt_output = buffer + page_size;
    json_buffer = buffer + page_size * 2;

    static struct option options[] =
    {
        { "probe", 2, 0, 'P' },
        { "wake", 1, 0, 'W' },
        { "broadcast", 0, 0, 'B' },
        { "local-port", 1, 0, 'L' },
        { "remote-host", 1, 0, 'H' },
        { "remote-port", 1, 0, 'R' },
        { "interface", 1, 0, 'I' },
        { "json", 0, 0, 'j' },
        { "verbose", 0, 0, 'v' },
        { "help", 0, 0, 'h' },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1 ;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "PW:BL:H:R:I:jvh?", options, &o)) == -1) break;
        switch (rc) {
        case 'P':
            probe = 1;
            break;
        case 'W':
            cred = strdup(optarg);
            break;
        case 'B':
            broadcast = 1;
            break;
        case 'L':
            port_local = (short)atoi(optarg);
            break;
        case 'H':
            host_remote = strdup(optarg);
            break;
        case 'R':
            port_remote = (short)atoi(optarg);
            break;
        case 'I':
            iface = strdup(optarg);
            break;
        case 'j':
            json = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case '?':
            fprintf(stderr,
                "Try %s --help for more information.\n", argv[0]);
            return _EXIT_BADOPTION;
        case 'h':
            usage(0);
            break;
        }
    }

    if (cred == NULL && !probe) {
        fprintf(stderr, "A user credential is required.\n");
        return _EXIT_NOUSERCRED;
    }

    if (!broadcast && host_remote == NULL) {
        fprintf(stderr, "Either broadcast or remote host is required.\n");
        return _EXIT_NOHOSTADDR;
    }

    if (broadcast && host_remote != NULL) {
        fprintf(stderr, "Broadcast and remote host can not both be set.\n");
        return _EXIT_BADHOSTADDR;
    }

    struct sockaddr_in sa_local, sa_remote;

    memset(&sa_local, 0, sizeof(struct sockaddr_in));
    memset(&sa_remote, 0, sizeof(struct sockaddr_in));

    sa_local.sin_family = AF_INET;
    sa_local.sin_port = htons(port_local);

    sa_remote.sin_family = AF_INET;

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    if (bind(sd, (struct sockaddr *)&sa_local, sizeof(struct sockaddr_in)) == -1) {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    if (broadcast) {
        sa_remote.sin_addr.s_addr = INADDR_BROADCAST;

        int enable = 1;
        if ((setsockopt(sd,
            SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable))) == -1) {
            fprintf(stderr, "Error enabling broadcasts: %s\n", strerror(errno));
            return _EXIT_SOCKET;
        }
    }
    else {
        struct addrinfo hints, *result;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = sa_remote.sin_family;

        if ((rc = getaddrinfo(host_remote, NULL, &hints, &result)) != 0) {
            fprintf(stderr, "Error resolving remote address: %s: %s\n",
                host_remote, gai_strerror(rc));
            return _EXIT_HOSTNOTFOUND;
        }

        struct sockaddr_in *sa_in_src =
            (struct sockaddr_in *)result->ai_addr;
        sa_remote.sin_addr.s_addr = sa_in_src->sin_addr.s_addr;
        freeaddrinfo(result);
    }

    if (iface != NULL) {
        if (iface_get_bcast_addr(iface, &sa_remote) != 0)
            return _EXIT_SOCKET;
    }

    struct timeval tv;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (setsockopt(sd,
        SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1) {
        fprintf(stderr, "Error setting socket read time-out: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    sprintf(pkt_output,
        "SRCH * HTTP/1.1\n"
        "device-discovery-protocol-version:%s\n",
        _DDP_VERSION);

    reply = malloc(sizeof(struct ddp_reply));
    memset(reply, 0, sizeof(struct ddp_reply));

    ssize_t bytes;
    socklen_t sock_size;

    if (verbose) fprintf(stderr, "Scanning");

    int found_device = 0;
    for (int i = 0; i < probes; i++) {
        sa_remote.sin_port = htons(port_remote);
        bytes = sendto(sd, pkt_output, strlen(pkt_output) + 1, 0,
            (struct sockaddr *)&sa_remote, sizeof(struct sockaddr_in));
        if (bytes < 0) {
            fprintf(stderr, "Error writing packet: %s\n", strerror(errno));
        }

        sock_size = sizeof(struct sockaddr_in);
        bytes = recvfrom(sd, pkt_input, page_size, 0,
            (struct sockaddr *)&sa_remote, &sock_size);
        if (bytes < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "Error reading packet: %s\n", strerror(errno));
                return _EXIT_SOCKET;
            }
        }
        else {
            if (ddp_parse(pkt_input, reply) != 0) continue;
            found_device = 1;
            break;
        }

        if (verbose) fputc('.', stderr);
    }

    if (verbose) fputc('\r', stderr);

    if (!found_device) {
        fprintf(stderr, "No device found.\n");
        return _EXIT_DEVNOTFOUND;
    }
    else {
        fprintf(stderr, "Device found");
        if (verbose) {
            fprintf(stderr, ": %s [%s/%s]",
                reply->host_name, reply->host_type, reply->host_id);
            switch (reply->code) {
            case 200:
                if (reply->running_app_name != NULL) {
                    fprintf(stderr, ": %s (%s)",
                        reply->running_app_name, reply->running_app_titleid);
                }
                else fprintf(stderr, ": Home Screen");
                break;
            case 620:
                fprintf(stderr, ": Standby");
                break;
            default:
                fprintf(stderr, ": Unknown status (%hd)", reply->code);
                break;
            }
        }
        else fputc('.', stderr);
        fputc('\n', stderr);

        if (probe && json) json_output(reply);
    }

    if (probe)
        return _EXIT_SUCCESS;

    sprintf(pkt_output,
        "WAKEUP * HTTP/1.1\n"
        "client-type:%s\n"
        "auth-type:%s\n"
        "model:%s\n"
        "app-type:%s\n"
        "user-credential:%s\n"
        "device-discovery-protocol-version:%s\n",
        _DDP_CLIENTTYPE, _DDP_AUTHTYPE, _DDP_MODEL, _DDP_APPTYPE, cred, _DDP_VERSION);

    if (verbose) fprintf(stderr, "Sending wake-up...\n");

    sa_remote.sin_port = htons(port_remote);
    bytes = sendto(sd, pkt_output, strlen(pkt_output), 0,
        (struct sockaddr *)&sa_remote, sizeof(struct sockaddr_in));
    if (bytes < 0) {
        fprintf(stderr, "Error writing packet: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    return _EXIT_SUCCESS;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
