#include <openssl/ssl.h>
#include "ssl.h"

int ssl_ciphers(SSL_CTX *ctx,const char *ciphers) {
  if (!ciphers) return 1;
  return SSL_CTX_set_cipher_list(ctx,ciphers);
}

