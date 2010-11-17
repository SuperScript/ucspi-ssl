#include <EXTERN.h>
#include <perl.h>
#include "strerr.h"
#include "stralloc.h"
#include "str.h"

#ifndef eval_pv
#define eval_pv perl_eval_pv
#endif

#ifndef call_argv
#define call_argv perl_call_argv
#endif

extern const char *self;

/* ActiveState Perl requires this be called my_perl */
static PerlInterpreter *my_perl = 0;

static void usage(void) {
  strerr_warn4(self,": usage: ",self," sslargs file sub args",0);
  _exit(100);
}

static stralloc newenv = {0};
static char *trivenv[] = { 0 };
static char **perlenv = trivenv;
static char **origenv = 0;

void env_append(const char *c) {
  if (!stralloc_append(&newenv,c))
    strerr_die2x(111,self,"out of memory");
}

#define EXTERN_C extern

EXTERN_C void xs_init() {
}

void server(int argc,char * const *argv) {
  char *prog[] = { "", *argv };
  int i;
  int j;
  int split;
  const char *x;

  ++argv; --argc;
  if (!argv) usage();
  if (!*argv) usage();

  origenv = environ;
  environ = perlenv;

  if (!my_perl) {
    my_perl = perl_alloc();
    if (!my_perl) strerr_die2x(111,self,"out of memory");
    perl_construct(my_perl);
    if (perl_parse(my_perl,xs_init,2,prog,trivenv))
      strerr_die2x(111,self,"perl_parse failed");

    if (perl_run(my_perl))
      strerr_die2x(111,self,"perl_run failed");
  }

  if (!stralloc_copys(&newenv,"%ENV=("))
    strerr_die2x(111,self,"out of memory");
  for(i = 0;origenv[i];++i) {
    x = origenv[i];
    if (!x) continue;
    split = str_chr(x,'=');
    env_append("'");
    for (j = 0;j < split;++j) {
      if (*x == '\'' || *x == '\\') env_append("\\");
      env_append(x++);
    }
    env_append("'");
    env_append(",");
    env_append("'");
    if (*x == '=') ++x;
    while (*x) {
      if (*x == '\'' || *x == '\\') env_append("\\");
      env_append(x++);
    }
    env_append("'");
    env_append(",");
  }
  env_append(")");
  env_append("\0");

  ENTER;
  SAVETMPS;
  eval_pv(newenv.s,TRUE);
  FREETMPS;
  LEAVE;

  if (call_argv(*argv,G_VOID|G_DISCARD,argv + 1))
    strerr_die2x(111,self,"interpreter failed");

  perlenv = environ;
  environ = origenv;
}
