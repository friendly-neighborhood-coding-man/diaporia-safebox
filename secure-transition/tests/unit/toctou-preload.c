/* Test-only helper. After the first statx(AT_SYMLINK_NOFOLLOW) of TOCTOU_PATH,
 * replace that path with a symlink to TOCTOU_DEST. Used to interleave a
 * same-directory replacement between a path check and a later path read.
 * Not part of the installer. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifndef SYS_statx
#define SYS_statx 332
#endif
extern int unlink(const char *);
extern int symlink(const char *, const char *);
extern char *getenv(const char *);
static int swapping = 0;
static int swapped = 0;
static void maybe_swap(const char *path) {
  if (swapping || swapped || !path) return;
  const char *want = getenv("TOCTOU_PATH");
  const char *dest = getenv("TOCTOU_DEST");
  if (!want || !dest || strcmp(path, want) != 0) return;
  swapping = 1;
  swapped = 1;
  if (unlink(path) != 0) { swapping = 0; return; }
  if (symlink(dest, path) != 0) { swapping = 0; return; }
  swapping = 0;
}
long syscall(long n, ...) {
  static long (*real)(long, ...) = 0;
  if (!real) real = (long (*)(long, ...))dlsym(RTLD_NEXT, "syscall");
  va_list ap;
  va_start(ap, n);
  long a1 = va_arg(ap, long);
  long a2 = va_arg(ap, long);
  long a3 = va_arg(ap, long);
  long a4 = va_arg(ap, long);
  long a5 = va_arg(ap, long);
  long a6 = va_arg(ap, long);
  va_end(ap);
  long rc = real(n, a1, a2, a3, a4, a5, a6);
  /* AT_SYMLINK_NOFOLLOW is 0x100. statx flags are the third argument. */
  if (!swapping && n == SYS_statx && (a3 & 0x100)) maybe_swap((const char *)a2);
  return rc;
}
