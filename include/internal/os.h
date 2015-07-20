#ifndef BCD_INTERNAL_OS_H
#define BCD_INTERNAL_OS_H

#include "bcd.h"

int bcd_os_oom_adjust(bcd_error_t *);
time_t bcd_os_time(void);

#endif /* BCD_INTERNAL_OS_H */
