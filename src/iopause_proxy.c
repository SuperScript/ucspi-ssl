#include "iopause.h"
#include "buffer.h"
#include "fd.h"
#include "error.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

/* copy fd0 -> fdleft, copy fdright -> fd1 */
int iopause_proxy(int fd0,int fdleft,int fdright,int fd1,unsigned int timeout) {
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[4];
  iopause_fd *io0;
  iopause_fd *ioleft;
  iopause_fd *io1;
  iopause_fd *ioright;
  int xlen;
  int r;
  int leftstatus;
  int leftlen;
  int leftpos;
  int rightstatus;
  int rightlen;
  int rightpos;
  char leftbuf[512];
  char rightbuf[512];

  leftstatus = 0;
  leftlen = 0;
  leftpos = 0;
  rightstatus = 0;
  rightlen = 0;
  rightpos = 0;
  for (;;) {
    xlen = 0;

    io0 = 0;
    if (leftstatus == 0) {
      io0 = &x[xlen++];
      io0->fd = fd0;
      io0->events = IOPAUSE_READ;
    }
    ioleft = 0;
    if (leftstatus == 1) {
      ioleft = &x[xlen++];
      ioleft->fd = fdleft;
      ioleft->events = IOPAUSE_WRITE;
    }

    ioright = 0;
    if (rightstatus == 0) {
      ioright = &x[xlen++];
      ioright->fd = fdright;
      ioright->events = IOPAUSE_READ;
    }
    io1 = 0;
    if (rightstatus == 1) {
      io1 = &x[xlen++];
      io1->fd = fd1;
      io1->events = IOPAUSE_WRITE;
    }

    taia_now(&stamp);
    taia_uint(&deadline,timeout);
    taia_add(&deadline,&stamp,&deadline);
    iopause(x,xlen,&deadline,&stamp);

    if (io0 && io0->revents) {
      r = buffer_unixread(fd0,leftbuf,sizeof leftbuf);
      if (r > 0) {
        leftstatus = 1; leftpos = 0; leftlen = r;
      }
      else if (r == -1 && errno != error_again) {
	leftstatus = -2; /* read error */
	break;
      }
      else if (r == 0) {
        leftstatus = -1; /* EOF */
        fd_shutdown(fd0,0);
	fd_shutdown(fdleft,1);
      }
    }

    if (ioleft && ioleft->revents) {
      r = buffer_unixwrite(fdleft,leftbuf + leftpos,leftlen - leftpos);
      if (r >= 0) {
	leftpos += r;
	if (leftpos == leftlen)
	  leftstatus = 0;
      }
      else if (r == -1 && errno != error_again) {
	leftstatus = -3; /* write error */
	break;
      }
    }

    if (ioright && ioright->revents) {
      r = buffer_unixread(fdright,rightbuf,sizeof rightbuf);
      if (r > 0) {
	rightstatus = 1; rightpos = 0; rightlen = r;
      }
      else if (r == -1 && errno != error_again) {
	rightstatus = -2; /* read error */
	break;
      }
      else if (r == 0) {
	rightstatus = -1; /* EOF */
	fd_shutdown(fdright,0);
	fd_shutdown(fd1,1);
      }
    }

    if (io1 && io1->revents) {
      r = buffer_unixwrite(fd1,rightbuf + rightpos,rightlen - rightpos);
      if (r >= 0) {
	rightpos += r;
	if (rightpos == rightlen)
	  rightstatus = 0;
      }
      else if (r == -1 && errno != error_again) {
	rightstatus = -3; /* write error */
      }
    }

    if (leftstatus < 0 && rightstatus < 0) break;
  }

  if (leftstatus < -1) {
    fd_shutdown(fd0,0);
    fd_shutdown(fdleft,1);
  }
  if (rightstatus < -1) {
    fd_shutdown(fdright,0);
    fd_shutdown(fd1,1);
  }
  close(fd0); close(fdleft); close(fdright); close(fd1);
  /* no error => 0, read error => -1, write error => -2 */
  /* return the lesser value reported */
  if (leftstatus < rightstatus) return ++leftstatus;
  return ++rightstatus;
}
