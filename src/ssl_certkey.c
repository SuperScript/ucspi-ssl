#include <openssl/ssl.h>
#include "ssl.h"

int ssl_certkey(SSL_CTX *ctx,const char *certfile,const char *keyfile,pem_password_cb *passwd_cb)
{
  if (!certfile) return 0;

  if (SSL_CTX_use_certificate_chain_file(ctx,certfile) != 1)
    return -1;

  if (!keyfile) keyfile = certfile;
  SSL_CTX_set_default_passwd_cb(ctx,passwd_cb);
  if (SSL_CTX_use_RSAPrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM) != 1)
    return -2;

  if (SSL_CTX_check_private_key(ctx) != 1)
    return -3;

  return 0;
}

