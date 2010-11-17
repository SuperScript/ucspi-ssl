#include "scan.h"

unsigned int scan_uint(register const char *s,register unsigned int *u)
{
  register unsigned int pos; unsigned long result;
  pos = scan_ulong(s,&result);
  *u = result; return pos;
}
