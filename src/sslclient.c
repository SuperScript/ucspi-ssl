#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include "ssl.h"
#include "sig.h"
#include "exit.h"
#include "sgetopt.h"
#include "uint16.h"
#include "fmt.h"
#include "scan.h"
#include "str.h"
#include "ip4.h"
#include "uint16.h"
#include "socket.h"
#include "fd.h"
#include "stralloc.h"
#include "buffer.h"
#include "getln.h"
#include "error.h"
#include "strerr.h"
#include "pathexec.h"
#include "timeoutconn.h"
#include "remoteinfo.h"
#include "dns.h"
#include "auto_cafile.h"
#include "auto_cadir.h"
#include "auto_ciphers.h"
#include "byte.h"
#include "ndelay.h"
#include "wait.h"
#include "ucspitls_master.h"

#define FATAL "sslclient: fatal: "
#define CONNECT "sslclient: unable to connect to "

void nomem(void) {
  strerr_die2x(111,FATAL,"out of memory");
}
void env(const char *s,const char *t) {
  if (!pathexec_env(s,t)) nomem();
}
int error_warn(const char *x) {
  if (!x) return 0;
  strerr_warn2("sslclient: ",x,0);
  return 0;
}
void usage(void) {
  strerr_die1x(100,"sslclient: usage: sslclient \
[ -3hHrRdDqQveEsSnNxX ] \
[ -i localip ] \
[ -p localport ] \
[ -T timeoutconn ] \
[ -l localname ] \
[ -t timeoutinfo ] \
[ -a cafile ] \
[ -A cadir ] \
[ -c certfile ] \
[ -C ciphers ] \
[ -k keyfile ] \
[ -V verifydepth ] \
[ -w progtimeout ] \
host port program");
}

int verbosity = 1;
int flagdelay = 0;
int flagremoteinfo = 1;
int flagremotehost = 1;
int flag3 = 0;
int flagsslenv = 0;
int flagtcpenv = 0;
int flagsslwait = 0;
unsigned long itimeout = 26;
unsigned long ctimeout[2] = { 2, 58 };
struct ssl_io_opt io_opt;

char iplocal[4] = { 0,0,0,0 };
uint16 portlocal = 0;
const char *forcelocal = 0;

char ipremote[4];
uint16 portremote;

const char *hostname;
int flagname = 1;
int flagservercert = 1;
static stralloc addresses;
static stralloc moreaddresses;

static stralloc tmp;
static stralloc fqdn;
char strnum[FMT_ULONG];
char ipstr[IP4_FMT];

char seed[128];

char bspace[16];
buffer b;

SSL_CTX *ctx;
const char *certfile = 0;
const char *keyfile = 0;
const char *cafile = auto_cafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
stralloc password = {0};
int match = 0;
int verifydepth = 1;

int pi[2];
int po[2];
int pt[2];

void read_passwd() {
  if (!password.len) {
    buffer_init(&b,buffer_unixread,3,bspace,sizeof bspace);
    if (getln(&b,&password,&match,'\0') == -1)
      strerr_die2sys(111,FATAL,"unable to read password: ");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buf,int size,int rwflag,void *userdata) {
  if (size < password.len)
    strerr_die2x(111,FATAL,"password too long");

  byte_copy(buf,password.len,password.s);
  return password.len;
}

SSL *start_ssl(int s) {
  int cloop;
  SSL *ssl;

  ctx = ssl_client();
  ssl_errstr();
  if (!ctx)
    strerr_die2x(111,FATAL,"unable to create SSL context");

  switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
    case -1: strerr_die2x(111,FATAL,"unable to load certificate");
    case -2: strerr_die2x(111,FATAL,"unable to load key pair");
    case -3: strerr_die2x(111,FATAL,"key does not match certificate");
    default: break;
  }

  if (!ssl_ca(ctx,cafile,cadir,verifydepth))
    strerr_die2x(111,FATAL,"unable to load CA list");

  if (!ssl_ciphers(ctx,ciphers))
    strerr_die2x(111,FATAL,"unable to set cipher list");

  ssl = ssl_new(ctx,s);
  if (!ssl) strerr_die2x(111,FATAL,"unable to create SSL instance");

  for (cloop = 0;cloop < 2;++cloop) {
    if (!ssl_timeoutconn(ssl,ctimeout[cloop])) goto SSLCONNECTED;
    if (!cloop && ctimeout[1]) continue;
    strerr_warn2(FATAL,"unable to SSL connect:",&strerr_sys);
    ssl_error(error_warn);
  }
  return NULL; /* Failure */

 SSLCONNECTED:
  ndelay_off(s);

  if (verbosity >= 2)
    strerr_warn1("sslclient: ssl connect",0);

  if (flagservercert)
    switch(ssl_verify(ssl,flagname ? hostname : 0)) {
      case -1:
	strerr_die2x(111,FATAL,"unable to verify server certificate");
      case -2:
	strerr_die2x(111,FATAL,"no server certificate");
      case -3:
	strerr_die2x(111,FATAL,"server name does not match certificate");
      default: break;
    }

  if (!flagdelay)
    socket_tcpnodelay(s); /* if it fails, bummer */

  return ssl;
}

int main(int argc,char * const *argv) {
  unsigned long u;
  int opt;
  const char *x;
  int j;
  int s;
  int cloop;
  SSL *ssl = NULL;
  int wstat;
  int sslctl[2];
  char sslctl_cmd;
  stralloc ssl_env = { 0 };
  buffer ssl_env_buf;

  io_opt = ssl_io_opt_default;
  io_opt.timeout = 3600;

  dns_random_init(seed);

  close(6);
  close(7);
  sig_ignore(sig_pipe);
 
  while ((opt = getopt(argc,argv,"dDvqQhHrRi:p:t:T:l:a:A:c:C:k:V:3eEsSnN0xXw:yYjJ")) != opteof)
    switch(opt) {
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'l': forcelocal = optarg; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&itimeout); break;
      case 'T': j = scan_ulong(optarg,&ctimeout[0]);
		if (optarg[j] == '+') ++j;
		scan_ulong(optarg + j,&ctimeout[1]);
		break;
      case 'w': scan_uint(optarg,&io_opt.timeout); break;
      case 'i': if (!ip4_scan(optarg,iplocal)) usage(); break;
      case 'p': scan_ulong(optarg,&u); portlocal = u; break;
      case 'a': cafile = optarg; break;
      case 'A': cadir = optarg; break;
      case 'c': certfile = optarg; break;
      case 'C': ciphers = optarg; break;
      case 'k': keyfile = optarg; break;
      case 'V': scan_ulong(optarg,&u); verifydepth = u; break;
      case '3': flag3 = 1; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'N': flagname = 0; break;
      case 'n': flagname = 1; break;
      case 'x': flagservercert = 1; break;
      case 'X': flagservercert = 0; break;
      case 'y': flagsslwait = 1; break;
      case 'Y': flagsslwait = 0; break;
      case 'j': io_opt.just_shutdown = 1; break;
      case 'J': io_opt.just_shutdown = 0; break;
      default: usage();
    }
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;

  hostname = *argv;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = "127.0.0.1";
  if (str_equal(hostname,"0")) hostname = "127.0.0.1";

  x = *++argv;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    portremote = u;
  else {
    struct servent *se;
    se = getservbyname(x,"tcp");
    if (!se)
      strerr_die3x(111,FATAL,"unable to figure out port number for ",x);
    portremote = ntohs(se->s_port);
  }

  if (flag3) read_passwd();

  if (cafile && str_equal(cafile,"")) cafile = 0;
  if (cadir && str_equal(cadir,"")) cadir= 0;
  if (ciphers && str_equal(ciphers,"")) ciphers= 0;

  if (certfile && str_equal(certfile,"")) certfile = 0;
  if (keyfile && str_equal(keyfile,"")) keyfile = 0;

  if (!*++argv) usage();

  if (!stralloc_copys(&tmp,hostname)) nomem();
  if (dns_ip4_qualify(&addresses,&fqdn,&tmp) == -1)
    strerr_die4sys(111,FATAL,"temporarily unable to figure out IP address for ",hostname,": ");
  if (addresses.len < 4)
    strerr_die3x(111,FATAL,"no IP address for ",hostname);

  if (addresses.len == 4) {
    ctimeout[0] += ctimeout[1];
    ctimeout[1] = 0;
  }

  s = -1;
  for (cloop = 0;cloop < 2;++cloop) {
    if (!stralloc_copys(&moreaddresses,"")) nomem();
    for (j = 0;j + 4 <= addresses.len;j += 4) {
      s = socket_tcp();
      if (s == -1)
        strerr_die2sys(111,FATAL,"unable to create socket: ");
      if (socket_bind4(s,iplocal,portlocal) == -1)
        strerr_die2sys(111,FATAL,"unable to bind socket: ");
      if (timeoutconn(s,addresses.s + j,portremote,ctimeout[cloop]) == 0)
        goto CONNECTED;
      close(s);
      if (!cloop && ctimeout[1] && (errno == error_timeout)) {
	if (!stralloc_catb(&moreaddresses,addresses.s + j,4)) nomem();
      }
      else {
        strnum[fmt_ulong(strnum,portremote)] = 0;
        ipstr[ip4_fmt(ipstr,addresses.s + j)] = 0;
        strerr_warn5(CONNECT,ipstr," port ",strnum,": ",&strerr_sys);
      }
    }
    if (!stralloc_copy(&addresses,&moreaddresses)) nomem();
  }

  _exit(111);

  CONNECTED:

  env("PROTO","SSL");

  if (socket_local4(s,iplocal,&portlocal) == -1)
    strerr_die2sys(111,FATAL,"unable to get local address: ");

  strnum[fmt_ulong(strnum,portlocal)] = 0;
  env("SSLLOCALPORT",strnum);
  if (flagtcpenv) env("TCPLOCALPORT",strnum);
  ipstr[ip4_fmt(ipstr,iplocal)] = 0;
  env("SSLLOCALIP",ipstr);
  if (flagtcpenv) env("TCPLOCALIP",ipstr);

  x = forcelocal;
  if (!x)
    if (dns_name4(&tmp,iplocal) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  env("SSLLOCALHOST",x);
  if (flagtcpenv) env("TCPLOCALHOST",x);

  if (socket_remote4(s,ipremote,&portremote) == -1)
    strerr_die2sys(111,FATAL,"unable to get remote address: ");

  strnum[fmt_ulong(strnum,portremote)] = 0;
  env("SSLREMOTEPORT",strnum);
  if (flagtcpenv) env("TCPREMOTEPORT",strnum);
  ipstr[ip4_fmt(ipstr,ipremote)] = 0;
  env("SSLREMOTEIP",ipstr);
  if (flagtcpenv) env("TCPREMOTEIP",ipstr);
  if (verbosity >= 2)
    strerr_warn4("sslclient: connected to ",ipstr," port ",strnum,0);

  x = 0;
  if (flagremotehost)
    if (dns_name4(&tmp,ipremote) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  env("SSLREMOTEHOST",x);
  if (flagtcpenv) env("TCPREMOTEHOST",x);

  x = 0;
  if (flagremoteinfo)
    if (remoteinfo(&tmp,ipremote,portremote,iplocal,portlocal,itimeout) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  env("SSLREMOTEINFO",x);
  if (flagtcpenv) env("TCPREMOTEINFO",x);
  
  if (flagsslwait) {
    /* Create delayed SSL control socket */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sslctl) == -1) strerr_die2sys(111,FATAL,"unable to create socketpair: ");

    /* Copy the socket to file descriptors 6 and 7 right now, so we
     * don't use them for something else later.
     */
    if (fd_copy(6,s) == -1)
      strerr_die2sys(111,FATAL,"unable to set up descriptor 6: ");
    if (fd_copy(7,s) == -1)
      strerr_die2sys(111,FATAL,"unable to set up descriptor 7: ");
  } else {
    /* If we aren't delaying SSL, start it now, so we won't run the client if it fails */
    if (!(ssl = start_ssl(s))) {
      _exit(111);
    }
  }

  if (pipe(pi) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
  if (pipe(po) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
  if (pi[0] == 7) {
    if (pipe(pt) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
    close(pi[0]); close(pi[1]);
    pi[0] = pt[0]; pi[1] = pt[1];
  }
  if (po[1] == 6) {
    if (pipe(pt) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
    close(po[0]); close(po[1]);
    po[0] = pt[0]; po[1] = pt[1];
  }

  switch(opt = fork()) {
    case -1:
      /* Error */
      strerr_die2sys(111,FATAL,"unable to fork: ");
    case 0:
      /* Child runs after switch */
      break;
    default:
      /* Parent */
      close(pi[0]); close(po[1]);
      if (flagsslwait) {
	if (close(sslctl[1]) != 0) {
	  strerr_die2sys(111, FATAL, "Error closing SSL control socket: ");
	}

	/* This will exit on a fatal error or if the client quits
	 * without activating SSL
	 */
	sslctl_cmd = ucspitls_master_wait_for_activation(sslctl[0]);

	/* If we got here, SSL has been requested. */
	if (!(ssl = start_ssl(s))) {
	  _exit(111);
	}
	
	if (sslctl_cmd == 'Y') {
	  if (!ssl_client_env(ssl, &ssl_env)) nomem();
	  stralloc_0(&ssl_env); /* Add another NUL */
	  buffer_init(&ssl_env_buf,buffer_unixwrite,sslctl[0],NULL,0);
	  if (buffer_putflush(&ssl_env_buf, ssl_env.s, ssl_env.len) == -1) {
	    strerr_die2sys(111, FATAL, "unable to write SSL environment: ");
	  }
	} else if (sslctl_cmd != 'y') {
	  strerr_die2x(111,FATAL,"Unrecognized command on SSL socket");
	}
	if (close(sslctl[0]) != 0) {
	  strerr_die2sys(111, FATAL, "Error closing SSL control socket: ");
	}
      }

      if (verbosity >= 2)
	strerr_warn1("sslclient: ssl_io starting",0);
      
      if (ssl_io(ssl,pi[1],po[0],io_opt)) {
	strerr_warn2(FATAL,"unable to speak SSL:",&strerr_sys);
	ssl_error(error_warn);
	ssl_close(ssl);
	wait_pid(&wstat,opt);
	_exit(111);
      }
      ssl_close(ssl);
      if (wait_pid(&wstat,opt) > 0)
	_exit(wait_exitcode(wstat));
      _exit(0);
  }
  
  /* Child */
  close(pi[1]); close(po[0]); close(sslctl[0]);

  if (flagsslwait) {
    strnum[fmt_ulong(strnum,sslctl[1])]=0;
    env("SSLCTLFD",strnum);
    strnum[fmt_ulong(strnum,pi[0])]=0;
    env("SSLREADFD",strnum);
    strnum[fmt_ulong(strnum,po[1])]=0;
    env("SSLWRITEFD",strnum);
  } else {
    ssl_close(ssl); 
    if (fd_move(6,pi[0]) == -1)
      strerr_die2sys(111,FATAL,"unable to set up descriptor 6: ");
    if (fd_move(7,po[1]) == -1)
      strerr_die2sys(111,FATAL,"unable to set up descriptor 7: ");

    if (flagsslenv && !ssl_client_env(ssl,0)) nomem();
  }
  sig_uncatch(sig_pipe);

  pathexec(argv);
  strerr_die4sys(111,FATAL,"unable to run ",*argv,": ");
}
