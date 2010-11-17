#include "buffer.h"
#include "exit.h"

main()
{
  register int n;
  register char *x;
  char ch;

  for (;;) {
    n = buffer_feed(buffer_0);
    if (n < 0) _exit(111);
    if (!n) _exit(0);
    x = buffer_PEEK(buffer_0);
    buffer_SEEK(buffer_0,n);
    while (n > 0) {
      ch = *x++; --n;
      if (ch == '\n') buffer_PUTC(buffer_1,"\r"[0]);
      buffer_PUTC(buffer_1,ch);
    }
  }
}
