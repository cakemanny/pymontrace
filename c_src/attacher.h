#ifndef ATTACHER_H
#define ATTACHER_H

#define ATT_SUCCESS         0
#define ATT_FAIL            1   /* a simple failure, but no real harm... */
#define ATT_UNKNOWN_STATE   2   /* not known if the child was left in a bad */
                                /* state */
#define ATT_INTERRUPTED     3

int attach_and_execute(int pid, const char* python_code);

int execute_in_threads(int pid, uint64_t* tids, int count_tids,
        const char* python_code);


#endif /* ATTACHER_H */
