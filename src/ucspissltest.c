#include <stdio.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include "ucspitls.h"
#include "sgetopt.h"

void usage(char *progname, int exit_status) {
  printf("Usage: %s [-yYsScCvqQ]\n", progname);
  printf(
	 "\t-y: Delay SSL until SIGUSR1 is received\n"
	 "\t-Y: Disable delayed SSL; plaintext mode, or SSL handled in sslclient/sslserver (default)\n"
	 "\t-s: Send SSL environment\n"
	 "\t-S: Don't send SSL environment (default)\n"
	 "\t-c: Client mode, for use with sslclient\n"
	 "\t-C: Server mode, for use with sslserver (default)\n"
	 "\t-v: Verbose mode\n"
	 "\t-q: Quiet mode\n"
	 "\t-Q: Non-quiet, non-verbose output (default)\n"
	 );
  printf("Signals:\n"
	 "\tSIGUSR1: Switch to SSL mode (if running with -y)\n"
	 "\tSIGUSR2: Dump environment to stderr\n"
	 );
  printf("Examples:\n"
	 "  Delayed TLS server with no environment (send SIGUSR1 to start TLS):\n"
	 "\tenv DHFILE=./dh1024.pem CERTFILE=./localhost.cert KEYFILE=./localhost.key ./sslserver -3 3<localhost.pw -v -y $HOST $PORT ./ucspissltest -C -y\n"
	 "  Initial TLS server with environment:\n"
	 "\tenv DHFILE=./dh1024.pem CERTFILE=./localhost.cert KEYFILE=./localhost.key ./sslserver -3 3<localhost.pw -v -y $HOST $PORT ./ucspissltest -s -C\n"
	 "  Delayed TLS client with environment (send SIGUSR1 to start TLS):\n"
	 "\t./sslclient -s -X -y $HOST $PORT ./ucspissltest -c -s -y\n"
	 "  Initial TLS client with no environment:\n"
	 "\t./sslclient -X $HOST $PORT ./ucspissltest -c\n"
	 );
  
  exit(exit_status);
}

#define BUFSIZE 8192

static int fd_sets[2][2];
static int num_sets;

int start_ssl = 0;
int dump_env = 0;

/* Signal handler to set a flag to start SSL */
void request_ssl(int sig) {
  if (start_ssl == 0)
    start_ssl = 1;
}

/* Signal handler to set a flag to dump environment */
void request_dumpenv(int sig) {
  dump_env = 1;
}

int flagsslwait = 0;
int flagsslenv = 0;
int verbosity = 1;
int client = 0;

/* Simple test program for tcpclient / sslclient */
int main(int argc, char *argv[]) {
  fd_set read_fds;
  int selret, nr, max_read_fd, nw, total_written;
  char buf[BUFSIZE];
  int i;
  int opt;
  int readfd, writefd;

  while ((opt = getopt(argc, argv, "yYsSvqQcCh")) != opteof) {
    switch(opt) {
      case 'y': flagsslwait = 1; break;
      case 'Y': flagsslwait = 0; break;
      case 's': flagsslenv = 1; break;
      case 'S': flagsslenv = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'c': client = 1; break;
      case 'C': client = 0; break;
      case 'h': usage(argv[0],0); /* Exits */
      default: usage(argv[0],1); /* Exits */
    }
  }

  if (client) {
    /*
     * From sslclient, we have these file descriptors:
     *   0: Standard input (terminal)
     *   1: Standard output (terminal)
     *   2: Standard error (terminal)
     *   6: Remote read (network)
     *   7: Remote write (network)
     */
    num_sets = 2;
    fd_sets[0][0] = 0; fd_sets[0][1] = 7;
    fd_sets[1][0] = 6; fd_sets[1][1] = 1;
    readfd = 6; writefd = 7;
  } else {
    /* From sslserver, we have these file descriptors:
     *   0: Remote read (network)
     *   1: Remote write (network)
     *   2: Standard error (terminal)
     */
    num_sets = 1;
    fd_sets[0][0] = 0; fd_sets[0][1] = 1;
    readfd = 0; writefd = 1;
  }
  if (verbosity > 0 ) {
    fprintf(stderr,"%s started, pid %d\n", argv[0], getpid());
    if (flagsslwait) {
      fprintf(stderr,"Send USR1 to activate TLS\n");
    }
    fprintf(stderr,"Send USR2 to dump environment\n");
  }

  /* Initialize data structures for select */
  FD_ZERO(&read_fds);
  max_read_fd = -1;
  for(i=0;i<num_sets;++i) {
    if (max_read_fd < fd_sets[i][0]) {
      max_read_fd = fd_sets[i][0];
    }
  }

  if (flagsslwait) {
    signal(SIGUSR1, request_ssl);
  }
  signal(SIGUSR2, request_dumpenv);
  signal(SIGPIPE, SIG_IGN);

  /* Simple event loop */
  while (1) {
    /* Check for flags set in signal handlers */
    if (start_ssl == 1) {
      /* Flag to activate SSL */
      start_ssl = 2;
      if (verbosity > 0) {
	fprintf(stderr,"SSL requested, starting\n");
      }
      if (!ucspitls(flagsslenv,readfd,writefd)) {
	fprintf(stderr,"SSL activation failed\n");
	return 127;
      }
      if (verbosity > 0) {
	fprintf(stderr,"SSL complete\n");
      }
    }
    if (dump_env) {
      dump_env = 0;
      system("env >&2");
    }

    /* See what's readable with select().  Note this is not a
     * super-efficient implementation, it really is designed for
     * testing. */
    for(i=0;i<num_sets;++i) {
      FD_SET(fd_sets[i][0], &read_fds);
    }
    if ((selret = select(max_read_fd+1, &read_fds, NULL, NULL, NULL)) == -1) {
      switch(errno) {
        case EINTR:
	  /* Retry */
	  continue;
      default:
	fprintf(stderr,"select failed: %s\n",strerror(errno));
	return 1;
      }
    }

    /* Read from the readable FDs */
    for(i=0;i<num_sets;++i) {
      if (FD_ISSET(fd_sets[i][0], &read_fds)) {
	nr = read(fd_sets[i][0], buf, BUFSIZE);
	if (nr == 0) {
	  /* EOF */
	  if (verbosity > 0) {
	    fprintf(stderr,"fd %d closed\n", fd_sets[i][0]);
	  }
	  return fd_sets[i][0];
	} else if (nr < 0) {
	  /* Error */
	  fprintf(stderr,"read from fd %d failed: %s\n", fd_sets[i][0], strerror(errno));
	  return fd_sets[i][0];
	} else {
	  /* Successfully read nr bytes */
	  total_written = 0;
	  while (total_written < nr) {
	    nw = write(fd_sets[i][1], buf + total_written, nr - total_written);
	    if (nw <= 0) {
	      fprintf(stderr,"write to fd %d failed: %s\n", fd_sets[i][1], strerror(errno));
	      return fd_sets[i][1];
	    }
	    total_written += nw;
	  }
	}
      }
    }
  }
  return 0;
}
