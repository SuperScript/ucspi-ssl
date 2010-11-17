#include "buffer.h"
#include "exit.h"

main()
{
  register int n;
  register char *x;
  char ch;
  register int flagcr = 0;

  for (;;) {
    n = buffer_feed(buffer_0);
    if (n < 0) _exit(111);
    if (!n) {
      if (flagcr) buffer_PUTC(buffer_1,"\r"[0]);
      buffer_flush(buffer_1);
      _exit(0);
    }
    x = buffer_PEEK(buffer_0);
    buffer_SEEK(buffer_0,n);

    while (n > 0) {
      ch = *x++; --n;
      if (!flagcr) {
        if (ch == '\r') { flagcr = 1; continue; }
	buffer_PUTC(buffer_1,ch);
	continue;
      }
      if (ch != '\n') {
        buffer_PUTC(buffer_1,"\r"[0]);
        if (ch == '\r') continue;
      }
      flagcr = 0;
      buffer_PUTC(buffer_1,ch);
    }
  }
}
