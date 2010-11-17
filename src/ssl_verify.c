#include <openssl/ssl.h>
#include "ssl.h"
#include "case.h"
#include "strerr.h"

int ssl_verify(SSL *ssl,const char *hostname)
{
  X509 *cert;
  char buf[SSL_NAME_LEN];

  if (SSL_get_verify_result(ssl) != X509_V_OK) return -1;

  cert = SSL_get_peer_certificate(ssl);
  if (!cert) return -2;

  X509_NAME_get_text_by_NID(X509_get_subject_name(cert),NID_commonName,buf,sizeof buf);

  if (hostname) {
    buf[SSL_NAME_LEN - 1] = 0;
    if (case_diffs(hostname,buf) != 0) return -3;
  }

  return 0;
}

