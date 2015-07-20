#ifndef BCD_INTERNAL_CC_H
#define BCD_INTERNAL_CC_H

#define BCD_CC_SECTION(X) \
	__attribute__((section(X)))
#define BCD_CC_ALIGN(X) \
	__attribute__((aligned(X)))
#define BCD_MD_PAGESIZE	4096ULL
#define BCD_SECTION "BACKTRACE_BCD_SB"

#define BCD_CC_FORCE(M, R)	\
	__asm__ __volatile__("" : "=m" (M) : "q" (*(R)) : "memory");

#endif /* BCD_INTERNAL_CC_H */
