#include <openssl/ssl.h>
#include "ssl.h"
#include "ndelay.h"

SSL *ssl_new(SSL_CTX *ctx,int s)
{
  BIO *sbio;
  SSL *ssl;

  ssl = SSL_new(ctx);
  if (!ssl) return 0;
  sbio = BIO_new_socket(s,BIO_NOCLOSE);
  if (!sbio) return 0;
  SSL_set_bio(ssl,sbio,sbio);
  return ssl;
}

