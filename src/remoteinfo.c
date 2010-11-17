#include <unistd.h>
#include "fmt.h"
#include "buffer.h"
#include "socket.h"
#include "error.h"
#include "iopause.h"
#include "timeoutconn.h"
#include "remoteinfo.h"

static struct taia now;
static struct taia deadline;

static int mywrite(int fd,char *buf,int len)
{
  iopause_fd x;

  x.fd = fd;
  x.events = IOPAUSE_WRITE;
  for (;;) {
    taia_now(&now);
    iopause(&x,1,&deadline,&now);
    if (x.revents) break;
    if (taia_less(&deadline,&now)) {
      errno = error_timeout;
      return -1;
    }
  }
  return buffer_unixwrite(fd,buf,len);
}

static int myread(int fd,char *buf,int len)
{
  iopause_fd x;

  x.fd = fd;
  x.events = IOPAUSE_READ;
  for (;;) {
    taia_now(&now);
    iopause(&x,1,&deadline,&now);
    if (x.revents) break;
    if (taia_less(&deadline,&now)) {
      errno = error_timeout;
      return -1;
    }
  }
  return buffer_unixread(fd,buf,len);
}

static int doit(stralloc *out,int s,char ipremote[4],uint16 portremote,char iplocal[4],uint16 portlocal,unsigned int timeout)
{
  buffer b;
  char bspace[128];
  char strnum[FMT_ULONG];
  int numcolons;
  char ch;

  if (socket_bind4(s,iplocal,0) == -1) return -1;
  if (timeoutconn(s,ipremote,113,timeout) == -1) return -1;

  buffer_init(&b,mywrite,s,bspace,sizeof bspace);
  buffer_put(&b,strnum,fmt_ulong(strnum,portremote));
  buffer_put(&b," , ",3);
  buffer_put(&b,strnum,fmt_ulong(strnum,portlocal));
  buffer_put(&b,"\r\n",2);
  if (buffer_flush(&b) == -1) return -1;

  buffer_init(&b,myread,s,bspace,sizeof bspace);
  numcolons = 0;
  for (;;) {
    if (buffer_get(&b,&ch,1) != 1) return -1;
    if ((ch == ' ') || (ch == '\t') || (ch == '\r')) continue;
    if (ch == '\n') return 0;
    if (numcolons < 3) {
      if (ch == ':') ++numcolons;
    }
    else {
      if (!stralloc_append(out,&ch)) return -1;
      if (out->len > 256) return 0;
    }
  }
}

int remoteinfo(stralloc *out,char ipremote[4],uint16 portremote,char iplocal[4],uint16 portlocal,unsigned int timeout)
{
  int s;
  int r;

  if (!stralloc_copys(out,"")) return -1;

  taia_now(&now);
  taia_uint(&deadline,timeout);
  taia_add(&deadline,&now,&deadline);

  s = socket_tcp();
  if (s == -1) return -1;
  r = doit(out,s,ipremote,portremote,iplocal,portlocal,timeout);
  close(s);
  return r;
}
