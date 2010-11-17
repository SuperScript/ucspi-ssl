#include <openssl/err.h>
#include "ssl.h"

int ssl_error(int (*op)(const char *)) {
  unsigned long e;
  int r;

  e = ERR_get_error();
  if (!e) return 0;
  r = op(ERR_error_string(e,0));
  if (r) return r;
  return ssl_error(op);
}
