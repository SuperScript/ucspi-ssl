/* Public domain. */

#include "fd.h"
#include "error.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int fd_shutdown(int fd,int how) {
  if (shutdown(fd,how) == 0) return 0;
  if (errno != error_notsock) return -1;
  errno = 0;
  close(fd);
  return 0;
}
