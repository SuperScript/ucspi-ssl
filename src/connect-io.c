#include "exit.h"
#include "iopause.h"
#include "strerr.h"
#include "scan.h"
#include "ndelay.h"
#include "sig.h"

#define FATAL "connect-io: fatal: "

void die_usage(void) {
  strerr_die1x(100,"connect-io: usage: connect-io timeout fdr fdw");
}

int main(int argc,char * const *argv) {
  unsigned int timeout;
  int fdr;
  int fdw;

  timeout = 3600;
  if (argc < 4) die_usage();
  scan_uint(*++argv,&timeout);
  if (!timeout) --timeout;
  scan_uint(*++argv,&fdr);
  if (fdr < 0) die_usage();
  scan_uint(*++argv,&fdw);
  if (fdw < 0) die_usage();
  ndelay_on(0);
  ndelay_on(fdw);
  ndelay_on(fdr);
  ndelay_on(1);
  sig_ignore(sig_pipe);
  switch(iopause_proxy(0,fdw,fdr,1,timeout)) {
    case 0: _exit(0);
    case -1: strerr_die2x(111,FATAL,"read error");
    case -2: strerr_die2x(111,FATAL,"write error");
  }
  strerr_die2x(111,FATAL,"unknown error");
}
