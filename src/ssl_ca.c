#include <openssl/ssl.h>
#include "ssl.h"

int ssl_ca(SSL_CTX *ctx,const char *certfile,const char *certdir,int d)
{
  if (!SSL_CTX_load_verify_locations(ctx,certfile,certdir)) return 0;

  SSL_CTX_set_verify_depth(ctx,d);

  return 1;
}

