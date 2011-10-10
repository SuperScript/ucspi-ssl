#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include "ssl.h"
#include "uint16.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "ip4.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "getln.h"
#include "error.h"
#include "strerr.h"
#include "sgetopt.h"
#include "socket.h"
#include "ndelay.h"
#include "remoteinfo.h"
#include "rules.h"
#include "sig.h"
#include "dns.h"
#include "auto_cafile.h"
#include "auto_cadir.h"
#include "auto_ccafile.h"
#include "auto_dhfile.h"
#include "auto_certfile.h"
#include "auto_keyfile.h"
#include "auto_ciphers.h"
#include "iopause.h"
#include "coe.h"
#include "lock.h"

extern void server(int argcs,char * const *argvs);
const char *self;

int verbosity = 1;
int flagkillopts = 1;
int flagafter = 0;
int flagdelay = 0;
const char *banner = "";
int flagremoteinfo = 1;
int flagremotehost = 1;
int flagparanoid = 0;
int flagclientcert = 0;
int flagsslenv = 0;
int flagtcpenv = 0;
unsigned long timeout = 26;
unsigned long ssltimeout = 26;
struct ssl_io_opt io_opt;
int selfpipe[2];
int flagexit = 0;

static stralloc tcpremoteinfo;

uint16 localport;
char localportstr[FMT_ULONG];
char localip[4];
char localipstr[IP4_FMT];
static stralloc localhostsa;
const char *localhost = 0;
const char *lockfile = 0;
int fdlock;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
char remoteip[4];
char remoteipstr[IP4_FMT];
static stralloc remotehostsa;
char *remotehost = 0;
char *verifyhost = 0;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];

static stralloc tmp;
static stralloc fqdn;
static stralloc addresses;
stralloc envplus = {0};
stralloc envtmp = {0};

char bspace[16];
buffer b;

SSL_CTX *ctx;
const char *certfile = auto_certfile;
const char *keyfile = auto_keyfile;
stralloc password = {0};
int match = 0;
const char *cafile = auto_cafile;
const char *ccafile = auto_ccafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
int verifydepth = 1;
const char *dhfile = auto_dhfile;
int rsalen = 1024;

int pi[2];
int po[2];


X509 *cert;
char buf[SSL_NAME_LEN];

char **e;
char **e1;

/* ---------------------------- child */

#define DROP ": warning: dropping connection, "

int flagdeny = 0;
int flagallownorules = 0;
const char *fnrules = 0;

void drop_nomem(void) {
  strerr_die3sys(111,self,DROP,"out of memory");
}
void cats(const char *s) {
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(const char *ch) {
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(const char *s) {
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    append(&ch);
  }
  cats("...");
}
void env(const char *s,const char *t) {
  if (!s) return;
  if (!stralloc_copys(&envtmp,s)) drop_nomem();
  if (t) {
    if (!stralloc_cats(&envtmp,"=")) drop_nomem();
    if (!stralloc_cats(&envtmp,t)) drop_nomem();
  }
  if (!stralloc_0(&envtmp)) drop_nomem();
  if (!stralloc_cat(&envplus,&envtmp)) drop_nomem();
}
void env_set(void) {
  unsigned int elen;
  unsigned int i;
  unsigned int j;
  unsigned int split;
  unsigned int t;

  if (!stralloc_cats(&envplus,"")) return;

  elen = 0;
  for (i = 0;environ[i];++i)
    ++elen;
  for (i = 0;i < envplus.len;++i)
    if (!envplus.s[i])
      ++elen;

  e = (char **) alloc((elen + 1) * sizeof(char *));
  if (!e) return;

  elen = 0;
  for (i = 0;environ[i];++i)
    e[elen++] = environ[i];

  j = 0;
  for (i = 0;i < envplus.len;++i)
    if (!envplus.s[i]) {
      split = str_chr(envplus.s + j,'=');
      for (t = 0;t < elen;++t)
	if (byte_equal(envplus.s + j,split,e[t]))
	  if (e[t][split] == '=') {
	    --elen;
	    e[t] = e[elen];
	    break;
	  }
      if (envplus.s[j + split])
	e[elen++] = envplus.s + j;
      j = i + 1;
    }
  e[elen] = 0;

  e1 = environ;
  environ = e;
}
void env_reset(void) {
  if (e) {
    if (e != environ) strerr_die3x(111,self,DROP,"environ changed");
    alloc_free((char *)e);
  }

  environ = e1;
  envplus.len = 0;
}
int error_warn(const char *x) {
  if (!x) return 0;
  strerr_warn3(self,": ",x,0);
  return 0;
}
void drop_rules(void) {
  strerr_die5sys(111,self,DROP,"unable to read ",fnrules,": ");
}

void found(char *data,unsigned int datalen) {
  unsigned int next0;
  unsigned int split;

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	flagdeny = 1;
	break;
      case '+':
	split = str_chr(data + 1,'=');
	if (data[1 + split] == '=') {
	  data[1 + split] = 0;
	  env(data + 1,data + 1 + split + 1);
	}
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

int doit(int t) {
  int j;
  SSL *ssl;

  remoteipstr[ip4_fmt(remoteipstr,remoteip)] = 0;

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strerr_warn5(self,": pid ",strnum," from ",remoteipstr,0);
  }

  if (socket_local4(t,localip,&localport) == -1)
    strerr_die3sys(111,self,DROP,"unable to get local address: ");

  localipstr[ip4_fmt(localipstr,localip)] = 0;
  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

  if (!localhost)
    if (dns_name4(&localhostsa,localip) == 0)
      if (localhostsa.len) {
	if (!stralloc_0(&localhostsa)) drop_nomem();
	localhost = localhostsa.s;
      }
  env("PROTO","SSL");
  env("SSLLOCALIP",localipstr);
  env("SSLLOCALPORT",localportstr);
  env("SSLLOCALHOST",localhost);
  if (flagtcpenv) {
    env("TCPLOCALIP",localipstr);
    env("TCPLOCALPORT",localportstr);
    env("TCPLOCALHOST",localhost);
  }

  if (flagremotehost)
    if (dns_name4(&remotehostsa,remoteip) == 0)
      if (remotehostsa.len) {
	if (flagparanoid) {
	  verifyhost = remoteipstr;
	  if (dns_ip4(&tmp,&remotehostsa) == 0)
	    for (j = 0;j + 4 <= tmp.len;j += 4)
	      if (byte_equal(remoteip,4,tmp.s + j)) {
		flagparanoid = 0;
		break;
	      }
	  }
	if (!flagparanoid) {
	  if (!stralloc_0(&remotehostsa)) drop_nomem();
	  remotehost = remotehostsa.s;
	  verifyhost = remotehostsa.s;
	}
      }
  env("SSLREMOTEIP",remoteipstr);
  env("SSLREMOTEPORT",remoteportstr);
  env("SSLREMOTEHOST",remotehost);
  if (flagtcpenv) {
    env("TCPREMOTEIP",remoteipstr);
    env("TCPREMOTEPORT",remoteportstr);
    env("TCPREMOTEHOST",remotehost);
  }

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,remoteip,remoteport,localip,localport,timeout) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }
  env("SSLREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);
  if (flagtcpenv)
    env("TCPREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);

  if (fnrules) {
    int fdrules;
    flagdeny = 0;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != error_noent) drop_rules();
      if (!flagallownorules) drop_rules();
    }
    else {
      if (rules(found,fdrules,remoteipstr,remotehost,flagremoteinfo ? tcpremoteinfo.s : 0) == -1)
	drop_rules();
      close(fdrules);
    }
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,self)) drop_nomem();
    if (!stralloc_cats(&tmp,": ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipstr);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipstr);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) {
    close(t);
    return(0);
  }

  if (pipe(pi) == -1) strerr_die3sys(111,self,DROP,"unable to create pipe: ");
  if (pipe(po) == -1) strerr_die3sys(111,self,DROP,"unable to create pipe: ");

  ssl = ssl_new(ctx,t);
  if (!ssl) strerr_die3x(111,self,DROP,"unable to create SSL instance");
  if (ndelay_on(t) == -1)
    strerr_die3sys(111,self,DROP,"unable to set socket options: ");
  if (ssl_timeoutaccept(ssl,ssltimeout) == -1) {
    strerr_warn2(DROP,"unable to SSL accept:",0);
    ssl_error(error_warn);
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strerr_warn4(self,": ssl ",strnum," accept ",0);
  }

  if (flagclientcert) {
    switch(ssl_verify(ssl,verifyhost)) {
      case -1:
	strerr_die3x(111,self,DROP,"unable to verify client certificate");
      case -2:
	strerr_die3x(111,self,DROP,"no client certificate");
      case -3:
	strerr_die3x(111,self,DROP,"client name does not match certificate");
      default: break;
    }
  }

  switch(fork()) {
    case -1:
      strerr_die3sys(111,self,DROP,"unable to fork: ");
    case 0:
      close(pi[0]); close(po[1]);
      sig_uncatch(sig_child);
      sig_unblock(sig_child);
      if (ssl_io(ssl,pi[1],po[0],io_opt) == -1) {
	strerr_warn2(DROP,"unable to speak SSL:",0);
	ssl_error(error_warn);
	_exit(111);
      }
      _exit(0);
  }
  close(pi[1]); close(po[0]);

  if (flagsslenv && !ssl_server_env(ssl,&envplus)) drop_nomem();
  env_set();

  if (fd_move(0,pi[0]) == -1)
    strerr_die3sys(111,self,DROP,"unable to set up descriptor 0: ");
  if (fd_move(1,po[1]) == -1)
    strerr_die3sys(111,self,DROP,"unable to set up descriptor 1: ");

  if (flagkillopts)
    socket_ipoptionskill(t);
  if (!flagdelay)
    socket_tcpnodelay(t);

  if (*banner) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof bspace);
    if (buffer_putsflush(&b,banner) == -1)
      strerr_die3sys(111,self,DROP,"unable to print banner: ");
  }

  ssl_free(ssl);
  return 1;
}

void done(void) {
  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,self)) drop_nomem();
    if (!stralloc_cats(&tmp,": ")) drop_nomem();
    cats("done "); safecats(strnum); cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }
}


/* ---------------------------- parent */

#define FATAL ": fatal: "

void usage(void)
{
  strerr_warn4(self,"\
: usage: ",self," \
[ -13UXpPhHrRoOdDqQviIeEsS ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
[ -t timeout ] \
[ -T ssltimeout ] \
[ -w progtimeout ] \
[ -f lockfile ] \
host port program",0);
  _exit(100);
}

unsigned long limit = 40;
unsigned long numchildren = 0;

int flag1 = 0;
int flag3 = 0;
unsigned long backlog = 20;
unsigned long uid = 0;
unsigned long gid = 0;

void printstatus(void) {
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  strerr_warn5(self,": status: ",strnum,"/",strnum2,0);
}

void trigger(void) {
  buffer_unixwrite(selfpipe[1],"",1);
}

void sigterm(void) {
  int pid;

  flagexit = 1;
  pid = getpid();
  if (pid < 0) strerr_die2sys(111,FATAL,"cannot get pid: ");
  kill(-pid,SIGTERM);
  trigger();
}

void sigchld(void) {
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      strerr_warn5(self,": end ",strnum," status ",strnum2,0);
    }
    if (numchildren) --numchildren; printstatus();
    if (flagexit && !numchildren) _exit(0);
  }
  trigger();
}

void read_passwd(void) {
  if (!password.len) {
    buffer_init(&b,buffer_unixread,3,bspace,sizeof bspace);
    if (getln(&b,&password,&match,'\0') == -1)
      strerr_die3sys(111,self,FATAL,"unable to read password: ");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buff,int size,int rwflag,void *userdata) {
  if (size < password.len)
    strerr_die3x(111,self,FATAL,"password too long");

  byte_copy(buff,password.len,password.s);
  return password.len;
}

void spawn(int s,int argc,char * const *argv) {
  int t;

  while (numchildren >= limit) sig_pause();
  while (numchildren < limit) {
    ++numchildren; printstatus();
 
    switch(fork()) {
      case 0:
	sig_uncatch(sig_child);
	sig_unblock(sig_child);
	sig_uncatch(sig_term);
	sig_uncatch(sig_pipe);
	for (;;) {
	  if (lockfile) {
	    if (lock_ex(fdlock) == -1)
	      strerr_die5sys(111,self,FATAL,"unable to lock ",lockfile,": ");
	    t = socket_accept4(s,remoteip,&remoteport);
	    lock_un(fdlock);
	  }
	  else
	    t = socket_accept4(s,remoteip,&remoteport);

	  if (t == -1) continue;
	  if (!doit(t)) continue;
	  server(argc,argv);
	  close(0); close(1);
	  env_reset();
	  done();
	}
	break;
      case -1:
	strerr_warn3(self,DROP,"unable to fork: ",&strerr_sys);
	--numchildren; printstatus();
    }
  }
}

int main(int argc,char * const *argv) {
  const char *hostname;
  int opt;
  struct servent *se;
  char *x;
  unsigned long u;
  int s;
  iopause_fd io[2];
  char ch;
  struct taia deadline;
  struct taia stamp;

  io_opt = ssl_io_opt_default;
  io_opt.timeout = 3600;
 
  self = argv[0];
  while ((opt = getopt(argc,argv,"dDvqQhHrR1UXx:t:T:u:g:l:b:B:c:pPoO3IiEeSsaAf:w:jJ")) != opteof)
    switch(opt) {
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'c': scan_ulong(optarg,&limit); break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'B': banner = optarg; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'P': flagparanoid = 0; break;
      case 'p': flagparanoid = 1; break;
      case 'O': flagkillopts = 1; break;
      case 'o': flagkillopts = 0; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&timeout); break;
      case 'T': scan_ulong(optarg,&ssltimeout); break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
		x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case '1': flag1 = 1; break;
      case 'l': localhost = optarg; break;
      case '3': flag3 = 1; break;
      case 'I': flagclientcert = 0; break;
      case 'i': flagclientcert = 1; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'A': flagafter = 0; break;
      case 'a': flagafter = 1; break;
      case 'f': lockfile = optarg; break;
      case 'w': scan_uint(optarg,&io_opt.timeout); break;
      case 'j': io_opt.just_shutdown = 1; break;
      case 'J': io_opt.just_shutdown = 0; break;
      default: usage();
    }
  argc -= optind;
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;
 
  hostname = *argv++; --argc;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = "0.0.0.0";
  if (str_equal(hostname,"0")) hostname = "0.0.0.0";

  x = *argv++; --argc;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    localport = u;
  else {
    se = getservbyname(x,"tcp");
    if (!se)
      strerr_die4x(111,self,FATAL,"unable to figure out port number for ",x);
    localport = ntohs(se->s_port);
  }

  if (x = env_get("VERIFYDEPTH")) {
    scan_ulong(x,&u);
    verifydepth = u;
  }

  if (x = env_get("CAFILE")) cafile = x;
  if (cafile && str_equal(cafile,"")) cafile = 0;

  if (x = env_get("CCAFILE")) ccafile = x;
  if (ccafile && str_equal(ccafile,"")) ccafile = 0;
  if (!flagclientcert) ccafile = 0;

  if (x = env_get("CADIR")) cadir = x;
  if (cadir && str_equal(cadir,"")) cadir= 0;

  if (x = env_get("CERTFILE")) certfile = x;
  if (certfile && str_equal(certfile,"")) certfile = 0;

  if (x = env_get("KEYFILE")) keyfile = x;
  if (keyfile && str_equal(keyfile,"")) keyfile = 0;

  if (x = env_get("DHFILE")) dhfile = x;
  if (dhfile && str_equal(dhfile,"")) dhfile = 0;

  if (x = env_get("CIPHERS")) ciphers = x;
  if (ciphers && str_equal(ciphers,"")) ciphers = 0;

  if (setsid() == -1)
    if (getpgrp() != getpid())
      strerr_die3sys(111,self,FATAL,"unable to create process group: ");
    
  if (lockfile) {
    fdlock = open_append(lockfile);
    if (fdlock == -1)
      strerr_die5sys(111,self,FATAL,"unable to open ",lockfile,": ");
  }

  if (pipe(selfpipe) == -1)
    strerr_die3sys(111,self,FATAL,"unable to create pipe: ");
  coe(selfpipe[0]);
  coe(selfpipe[1]);
  ndelay_on(selfpipe[0]);
  ndelay_on(selfpipe[1]);

  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);
 
  if (!stralloc_copys(&tmp,hostname))
    strerr_die3x(111,self,FATAL,"out of memory");
  if (dns_ip4_qualify(&addresses,&fqdn,&tmp) == -1)
    strerr_die5sys(111,self,FATAL,"temporarily unable to figure out IP address for ",hostname,": ");
  if (addresses.len < 4)
    strerr_die4x(111,self,FATAL,"no IP address for ",hostname);
  byte_copy(localip,4,addresses.s);

  s = socket_tcp();
  if (s == -1)
    strerr_die3sys(111,self,FATAL,"unable to create socket: ");
  if (socket_bind4_reuse(s,localip,localport) == -1)
    strerr_die3sys(111,self,FATAL,"unable to bind: ");
  if (socket_local4(s,localip,&localport) == -1)
    strerr_die3sys(111,self,FATAL,"unable to get local address: ");
  if (socket_listen(s,backlog) == -1)
    strerr_die3sys(111,self,FATAL,"unable to listen: ");
  ndelay_off(s);

  if (!flagafter) {
    if (gid) if (prot_gid(gid) == -1)
      strerr_die2sys(111,FATAL,"unable to set gid: ");
    if (uid) if (prot_uid(uid) == -1)
      strerr_die2sys(111,FATAL,"unable to set uid: ");
  }

  localportstr[fmt_ulong(localportstr,localport)] = 0;
  if (flag1) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof bspace);
    buffer_puts(&b,localportstr);
    buffer_puts(&b,"\n");
    buffer_flush(&b);
  }
 
  if (flag3) read_passwd();

  ctx = ssl_server();
  ssl_errstr();
  if (!ctx) strerr_die3x(111,self,FATAL,"unable to create SSL context");

  switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
    case -1: strerr_die3x(111,self,FATAL,"unable to load certificate");
    case -2: strerr_die3x(111,self,FATAL,"unable to load key");
    case -3: strerr_die3x(111,self,FATAL,"key does not match certificate");
    default: break;
  }

  if (!ssl_ca(ctx,cafile,cadir,verifydepth))
    strerr_die3x(111,self,FATAL,"unable to load CA list");

  if (!ssl_cca(ctx,ccafile))
    strerr_die3x(111,self,FATAL,"unable to load client CA list");

  if (!ssl_params(ctx,dhfile,rsalen))
    strerr_die3x(111,self,FATAL,"unable to set cipher parameters");

  if (flagafter) {
    if (gid) if (prot_gid(gid) == -1)
      strerr_die2sys(111,FATAL,"unable to set gid: ");
    if (uid) if (prot_uid(uid) == -1)
      strerr_die2sys(111,FATAL,"unable to set uid: ");
  }

  if (!ssl_ciphers(ctx,ciphers))
    strerr_die2x(111,FATAL,"unable to set cipher list");

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strnum2[fmt_ulong(strnum2,rsalen)] = 0;
    strerr_warn5(self,": cafile ",strnum," ",cafile,0);
    strerr_warn5(self,": ccafile ",strnum," ",ccafile,0);
    strerr_warn5(self,": cadir ",strnum," ",cadir,0);
    strerr_warn5(self,": cert ",strnum," ",certfile,0);
    strerr_warn5(self,": key ",strnum," ",keyfile,0);
    /* XXX */
    buffer_puts(buffer_2,self);
    strerr_warn6(": param ",strnum," ",dhfile," ",strnum2,0);
  }

  close(0);
  close(1);
  printstatus();

  for (;;) {
    if (!flagexit) spawn(s,argc,argv);

    sig_unblock(sig_child);
    io[0].fd = selfpipe[0];
    io[0].events = IOPAUSE_READ;
    taia_now(&stamp);
    taia_uint(&deadline,3600);
    taia_add(&deadline,&stamp,&deadline);
    iopause(io,1,&deadline,&stamp);
    sig_block(sig_child);

    if (flagexit && !numchildren) _exit(0);
    while (buffer_unixread(selfpipe[0],&ch,1) == 1)
      ;
  }
}
