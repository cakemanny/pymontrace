#ifndef ATTACHER_H
#define ATTACHER_H

#include <stdint.h>

#define ATT_SUCCESS         0
#define ATT_FAIL            1   /* a simple failure, but no real harm... */
#define ATT_UNKNOWN_STATE   2   /* not known if the child was left in a bad */
                                /* state */
#define ATT_INTERRUPTED     3

int attach_and_execute(int pid, const char* python_code);

int execute_in_threads(int pid, uint64_t* tids, int count_tids,
        const char* python_code);

enum reap_result {
    REAP_SUCCESS,
    REAP_FAIL,
    REAP_UNKNOWN,
    REAP_TIMEOUT,
    REAP_BADARG,
    REAP_GONE,
    REAP_SIGNALLED,
};

/* The return type here is int rather than enum reap_result to avoid giving
   false impressions that the compiler will prevent us returning something
   not in that enum. */
int reap_process(int pid, int timeout_ms, int *exitstatus, int* signum);

#endif /* ATTACHER_H */
