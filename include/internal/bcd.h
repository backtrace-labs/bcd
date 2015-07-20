#ifndef BCD_INTERNAL_BCD_H
#define BCD_INTERNAL_BCD_H

#include "bcd.h"

void bcd_error_handler_default(enum bcd_event event, pid_t pid, pid_t tid,
    const char *message);
void bcd_error_set(bcd_error_t *, int, const char *);
void bcd_abort(void);

#endif /* BCD_INTERNAL_BCD_H */
