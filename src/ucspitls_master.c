#include <unistd.h>
#include <errno.h>
#include "wait.h"
#include "strerr.h"

#define FATAL "Fatal error in SSL activation: "

/* Returns UCSPI-TLS command character (y or Y) on success.
 * On failure or child exit, exits directly and does not return.
 */
char ucspitls_master_wait_for_activation(int fd) {
  char sslctl_read_ret;
  char sslctl_cmd;
  int wstat;

  /* Read the TLS command socket.  This will block until/unless
   * TLS is requested.
   */  
  while(1) {
    sslctl_read_ret = read(fd,&sslctl_cmd,1);
    if ( sslctl_read_ret == 1 ) {
      /* SSL was requested */
      break;
    } else if (sslctl_read_ret == 0) {
      /* EOF from client, it must have exited */
      if ((wait_pid(&wstat,-1)) <= 0) {
	strerr_die2sys(111, FATAL, "Error waiting for child socket: ");
      }
      _exit(wait_exitcode(wstat));
    } else if (sslctl_read_ret < 0) {
      /* Error.  Is it retryable? */
      if (errno == EAGAIN || errno == EINTR) {
	/* Do nothing, let the loop run again */
      } else {
	strerr_die2sys(111,FATAL,"Read error on SSL control descriptor");
      }
    } else {
      /* Too many characters read, should not really happen */
      strerr_die2x(111,FATAL,"Protocol error on SSL control descriptor: too many characters read");
    }
  }

  return sslctl_cmd;
}
