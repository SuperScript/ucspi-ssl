/* Public domain. */

#ifndef PATHEXEC_H
#define PATHEXEC_H

extern void pathexec_run(const char *,char * const *,char * const *);
extern int pathexec_env(const char *,const char *);
extern void pathexec(char * const *);

#endif
