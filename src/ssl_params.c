#include <openssl/ssl.h>
#include "ssl.h"

int ssl_params(SSL_CTX *ctx,const char *dhfile,int len)
{
  DH *dh;
  RSA *rsa;
  BIO *bio;

  if (dhfile) {
    dh = 0;
    bio = BIO_new_file(dhfile,"r");
    if (!bio) return 0;
    dh = PEM_read_bio_DHparams(bio,0,0,0);
    BIO_free(bio);
    if (!dh) return 0;
    if (!SSL_CTX_set_tmp_dh(ctx,dh)) return 0;
  }

  if (len) {
    rsa = RSA_generate_key(len,RSA_F4,0,0);
    if (!rsa) return 0;
    if (!SSL_CTX_set_tmp_rsa(ctx,rsa)) return 0;
  }

  return 1;
}

