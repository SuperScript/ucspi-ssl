#ifndef SSL_H
#define SSL_H

#include <openssl/ssl.h>
#include "stralloc.h"

#define SSL_NAME_LEN 256

struct ssl_io_opt {
  unsigned int timeout;
  unsigned int just_shutdown;
};
extern struct ssl_io_opt ssl_io_opt_default;

extern int ssl_errno;
extern int ssl_io(SSL *,int,int,struct ssl_io_opt);
extern SSL_CTX *ssl_context(SSL_METHOD *);
extern int ssl_timeoutconn(SSL *,unsigned int);
extern int ssl_timeoutaccept(SSL *,unsigned int);
extern SSL *ssl_new(SSL_CTX *,int);
extern int ssl_certkey(SSL_CTX *,const char *,const char *,pem_password_cb *);
extern int ssl_ca(SSL_CTX *,const char *,const char *,int);
extern int ssl_cca(SSL_CTX *,const char *);
extern int ssl_ciphers(SSL_CTX *,const char *);
extern int ssl_verify(SSL *,const char *);
extern int ssl_params(SSL_CTX *,const char *,int);
extern int ssl_server_env(SSL *,stralloc *);
extern int ssl_client_env(SSL *,stralloc *);
extern char *ssl_error_str(int);
extern int ssl_error(int (*)(const char *));

#define ssl_client() (ssl_context(SSLv23_client_method()))
#define ssl_server() (ssl_context(SSLv23_server_method()))
#define ssl_errstr() (SSL_load_error_strings())
#define ssl_free(ssl) (SSL_free((ssl)))
#define ssl_close(ssl) (close(SSL_get_fd((ssl))))

#define ssl_pending(ssl) (SSL_pending((ssl)))
#define ssl_shutdown(ssl) (SSL_shutdown((ssl)))
#define ssl_shutdown_pending(ssl) (SSL_get_shutdown((ssl)) & SSL_RECEIVED_SHUTDOWN)
#define ssl_shutdown_sent(ssl) (SSL_get_shutdown((ssl)) & SSL_SENT_SHUTDOWN)

#endif
