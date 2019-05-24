#ifndef __COMMON_H
#define __COMMON_H

/* Help keep our console messages clean and organzied */

#include <stdio.h>
//#include "msgio.h"
//#include <sgx_key_exchange.h>
//#include <sgx_report.h>

#if defined(__cplusplus)
extern "C" {
#endif

void edividerWithText(const char *text);
void edivider();

void dividerWithText(FILE *fd, const char *text);
void divider(FILE *fd);

int eprintf(const char *format, ...);
int eputs(const char *s);







#if defined(__cplusplus)
}
#endif

#endif
