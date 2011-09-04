#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#define BUFSIZE 16384

/* This is written in a simple style, not using the ucspi-ssl string
 * libraries, so it is easy to embed in other programs.
 */

/* Read a file descriptor from the environment, or return -1 on error
*/
static int fdenv(const char *envname) {
  char *fdstr;
  long fd;

  if (!(fdstr=getenv(envname)))
    return -1;
  errno = 0;
  fd = strtol(fdstr, NULL, 10);
  if (errno != 0) return -1;
  if (fd < 0 || fd > INT_MAX) return -1;

  return fd;
}

/* Activate UCSPI-TLS */
int ucspitls(int want_env, int readfd, int writefd)
{
  int fd;
  char *addenv = malloc(BUFSIZE);
  int curbufsize = BUFSIZE;
  int readret;
  int totalrb;
  
  /* Figure out our control FD */
  if ( (fd = fdenv("SSLCTLFD")) < 0) {
    return 0;
  }

  if (want_env) {
    /* Request the environment on the SSL control FD */
    
    if (write((int)fd, "Y", 1) < 1)
      return 0;
  } else {
    /* Activate SSL but don't request the environment */
    if (write((int)fd, "y", 1) < 1)
      return 0;
  }

    
  /* Read what is sent over the file descriptor.  This should
   * basically always happen in one read, so other situations are
   * handled correctly but inefficiently.
   */
  totalrb = 0;
  addenv[0] = '\0';
  while ((readret = read(fd,addenv + totalrb,curbufsize - totalrb)) > 0) {
    totalrb += readret;
    if (totalrb == curbufsize) {
      curbufsize += BUFSIZE;
      addenv = realloc(addenv, curbufsize);
    }
    }
  if (readret == -1) {
    fprintf(stderr,"Error reading SSL environment: %s\n",strerror(errno));
    return 0;
  }
  
  if (want_env) {
    /* Parse the variables we read, and add them to the environment */
    char *nextenv = addenv;
    while (*nextenv) {
      char *val = strchr(nextenv,'=');
      if (val && strncmp(nextenv,"SSL_",4) == 0) {
	*val = '\0';
	++val;
	setenv(nextenv,val,1);
      } else {
	val = nextenv; // So we will start searching in the right place
      }
      nextenv = strchr(val, '\0') + 1;
    }
  }
  
  /* Now get the new file descriptors for reading and writing, and dup
   * them to the client's read and write fd, respectively.  The client
   * should be sure to discard any buffered data from before encyption
   * was activated, to avoid any issues like CVE-2011-0411.
   */
  if ((fd = fdenv("SSLREADFD")) < 0)
    return 0;
  if (dup2((int)fd,readfd) == -1)
    return 0;
 
  if ((fd = fdenv("SSLWRITEFD")) < 0)
    return 0;
  if (dup2((int)fd,writefd) == -1)
    return 0;
 
  /* It worked! */
  return 1;
}
