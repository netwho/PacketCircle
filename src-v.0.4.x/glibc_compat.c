/*
 * glibc_compat.c — glibc 2.38 compatibility shim
 *
 * glibc 2.38+ (Ubuntu 24.04) redirects sscanf/strtoul to __isoc23_* variants
 * when _GNU_SOURCE is defined (via _GNU_SOURCE -> _ISOC2X_SOURCE -> C2X_STRTOL).
 * Binaries built there require GLIBC_2.38 and fail to dlopen on older distros.
 *
 * This file is compiled WITHOUT _GNU_SOURCE so the functions here call the
 * traditional sscanf/strtoul symbols (< GLIBC_2.38). Their weak visibility
 * means the linker satisfies __isoc23_* references in the plugin locally,
 * removing the GLIBC_2.38 dependency from the .so's dynamic symbol table.
 *
 * On systems with glibc >= 2.38 the strong symbols from libc.so.6 override
 * these weak ones at dlopen time — so behaviour is identical everywhere.
 *
 * IMPORTANT: this file must NOT be compiled with _GNU_SOURCE or _ISOC2X_SOURCE.
 * The CMakeLists.txt adds -U_GNU_SOURCE for this file specifically.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

__attribute__((weak))
int __isoc23_sscanf(const char *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vsscanf(s, fmt, ap);
    va_end(ap);
    return r;
}

__attribute__((weak))
unsigned long int __isoc23_strtoul(const char *nptr, char **endptr, int base)
{
    return strtoul(nptr, endptr, base);
}
