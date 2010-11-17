#include <unistd.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include "fmt.h"
#include "pathexec.h"
#include "ssl.h"
#include "stralloc.h"
#include "str.h"

static char strnum[FMT_ULONG];
static stralloc ctemp = {0};
static stralloc *envsa = 0;
static stralloc btemp = {0};
static stralloc etemp = {0};

#ifndef NID_x500UniqueIdentifier
#define NID_x500UniqueIdentifier NID_uniqueIdentifier
#endif

#define set_env_id(n,e,v) \
if (!set_env_name_entry((n),(e),(v))) return 0

static int env_val(const char *env,const char *val,int len) {
  if (envsa) {
    if (!stralloc_cats(envsa,env)) return 0;
    if (!stralloc_catb(envsa,"=",1)) return 0;
    if (!stralloc_catb(envsa,val,len)) return 0;
    if (!stralloc_0(envsa)) return 0;
    return 1;
  }
  if (!stralloc_copyb(&etemp,val,len)) return 0;
  if (!stralloc_0(&etemp)) return 0;
  return pathexec_env(env,etemp.s);
}

static int env_str(const char *env,const char *val) {
  if (envsa) {
    return env_val(env,val,str_len(val));
    if (!stralloc_cats(envsa,env)) return 0;
    if (!stralloc_catb(envsa,"=",1)) return 0;
    if (!stralloc_catb(envsa,val,str_len(val) + 1)) return 0;
    return 1;
  }
  return pathexec_env(env,val);
}

static int set_env_name_entry(X509_NAME *xname,const char *env,int nid) {
  int m;
  int n;
  X509_NAME_ENTRY *xne;

  if (!env) return 1;
  for (m = 0;m < sk_X509_NAME_ENTRY_num(xname->entries);m++) {
    xne = sk_X509_NAME_ENTRY_value(xname->entries,m);
    n = OBJ_obj2nid(xne->object);
    if (n == nid)
      if (!env_val(env,xne->value->data,xne->value->length)) return 0;
  }
  return 1;
}

int ssl_session_vars(SSL *ssl) {
  char *x;
  SSL_SESSION *session;
  int n;
  int m;
  SSL_CIPHER *cipher;
  unsigned char u;
  unsigned char c;

  if (!env_str("SSL_PROTOCOL",SSL_get_version(ssl)))
    return 0;

  session = SSL_get_session(ssl);
  x = session->session_id;
  n = session->session_id_length;
  if (!stralloc_ready(&btemp,2 * n)) return 0;
  btemp.len = 2 * n;
  while (n--) {
    u = x[n];
    c = '0' + (u & 15); if (c > '0' + 9) c += 'a' - '0' - 10;
    btemp.s[2 * n + 1] = c;
    u >>= 4;
    c = '0' + (u & 15); if (c > '0' + 9) c += 'a' - '0' - 10;
    btemp.s[2 * n] = c;
  }
  if (!env_val("SSL_SESSION_ID",btemp.s,btemp.len)) return 0;

  if (!env_str("SSL_CIPHER",SSL_get_cipher_name(ssl))) return 0;
  
  cipher = SSL_get_current_cipher(ssl);
  if (!cipher) return 0;
  n = SSL_CIPHER_get_bits(cipher,&m);
  if (!env_str("SSL_CIPHER_EXPORT",n < 56 ? "true" : "false")) return 0;
  if (!env_val("SSL_CIPHER_USEKEYSIZE",strnum,fmt_ulong(strnum,n))) return 0;
  if (!env_val("SSL_CIPHER_ALGKEYSIZE",strnum,fmt_ulong(strnum,m))) return 0;

  if (!env_str("SSL_VERSION_INTERFACE","ucspi-ssl")) return 0;
  if (!env_str("SSL_VERSION_LIBRARY",OPENSSL_VERSION_TEXT)) return 0;

  return 1;
}

static int ssl_client_bio_vars(X509 *cert,STACK_OF(X509) *chain,BIO *bio) {
  int n;
  int m;
  ASN1_STRING *astring;

  astring = X509_get_notBefore(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_CLIENT_V_START",btemp.s,btemp.len)) return 0;

  astring = X509_get_notAfter(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_CLIENT_V_END",btemp.s,btemp.len)) return 0;

  if (!PEM_write_bio_X509(bio,cert)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_CLIENT_CERT",btemp.s,btemp.len)) return 0;

  if (chain) {
    for (m = 0;m < sk_X509_num(chain);m++) {
      if (!stralloc_copys(&ctemp,"SSL_CLIENT_CERT_CHAIN_")) return 0;
      if (!stralloc_catb(&ctemp,strnum,fmt_ulong(strnum,m))) return 0;
      if (!stralloc_0(&ctemp)) return 0;

      if (m < sk_X509_num(chain)) {
	if (!PEM_write_bio_X509(bio,sk_X509_value(chain,m))) return 0;
	n = BIO_pending(bio);
	if (!stralloc_ready(&btemp,n)) return 0;
	btemp.len = n;
	n = BIO_read(bio,btemp.s,n);
	if (n != btemp.len) return 0;
	if (!env_val(ctemp.s,btemp.s,btemp.len)) return 0;
      }
    }
  }

  return 1;
}

static int ssl_client_vars(X509 *cert,STACK_OF(X509) *chain) {
  X509_NAME *xname;
  char *x;
  unsigned long u;
  int n;
  BIO *bio;

  if (!cert) return 1;

  if (!env_val("SSL_CLIENT_M_VERSION",strnum,fmt_ulong(strnum,X509_get_version(cert) + 1)))
    return 0;

  u = ASN1_INTEGER_get(X509_get_serialNumber(cert));
  if (!env_val("SSL_CLIENT_M_SERIAL",strnum,fmt_ulong(strnum,u)))
    return 0;

  xname = X509_get_subject_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_CLIENT_S_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_CLIENT_S_DN_C",NID_countryName);
  set_env_id(xname,"SSL_CLIENT_S_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_CLIENT_S_DN_L",NID_localityName);
  set_env_id(xname,"SSL_CLIENT_S_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_CLIENT_S_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_CLIENT_S_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_CLIENT_S_DN_T",NID_title);
  set_env_id(xname,"SSL_CLIENT_S_DN_I",NID_initials);
  set_env_id(xname,"SSL_CLIENT_S_DN_G",NID_givenName);
  set_env_id(xname,"SSL_CLIENT_S_DN_S",NID_surname);
  set_env_id(xname,"SSL_CLIENT_S_DN_D",NID_description);
#if OPENSSL_VERSION_NUMBER >= 0x00907000
  set_env_id(xname,"SSL_CLIENT_S_DN_UID",NID_x500UniqueIdentifier);
#else
  set_env_id(xname,"SSL_CLIENT_S_DN_UID",NID_uniqueIdentifier);
#endif
  set_env_id(xname,"SSL_CLIENT_S_DN_Email",NID_pkcs9_emailAddress);

  xname = X509_get_issuer_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_CLIENT_I_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_CLIENT_I_DN_C",NID_countryName);
  set_env_id(xname,"SSL_CLIENT_I_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_CLIENT_I_DN_L",NID_localityName);
  set_env_id(xname,"SSL_CLIENT_I_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_CLIENT_I_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_CLIENT_I_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_CLIENT_I_DN_T",NID_title);
  set_env_id(xname,"SSL_CLIENT_I_DN_I",NID_initials);
  set_env_id(xname,"SSL_CLIENT_I_DN_G",NID_givenName);
  set_env_id(xname,"SSL_CLIENT_I_DN_S",NID_surname);
  set_env_id(xname,"SSL_CLIENT_I_DN_D",NID_description);
#if OPENSSL_VERSION_NUMBER < 0x0090700fL
  set_env_id(xname,"SSL_CLIENT_I_DN_UID",NID_uniqueIdentifier);
#else
  set_env_id(xname,"SSL_CLIENT_I_DN_UID",NID_x500UniqueIdentifier);
#endif
  set_env_id(xname,"SSL_CLIENT_I_DN_Email",NID_pkcs9_emailAddress);

  n = OBJ_obj2nid(cert->cert_info->signature->algorithm);
  if (!env_str("SSL_CLIENT_A_SIG",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  n = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (!env_str("SSL_CLIENT_A_KEY",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  bio = BIO_new(BIO_s_mem());
  if (!bio) return 0;
  n = ssl_client_bio_vars(cert,chain,bio);
  BIO_free(bio);
  if (!n) return 0;

  return 1;
}

static int ssl_server_bio_vars(X509 *cert,STACK_OF(X509) *chain,BIO *bio) {
  int n;
  int m;
  ASN1_STRING *astring;

  astring = X509_get_notBefore(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_SERVER_V_START",btemp.s,btemp.len)) return 0;

  astring = X509_get_notAfter(cert);
  if (!ASN1_UTCTIME_print(bio,astring)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_SERVER_V_END",btemp.s,btemp.len)) return 0;


  if (!PEM_write_bio_X509(bio,cert)) return 0;
  n = BIO_pending(bio);
  if (!stralloc_ready(&btemp,n)) return 0;
  btemp.len = n;
  n = BIO_read(bio,btemp.s,n);
  if (n != btemp.len) return 0;
  if (!env_val("SSL_SERVER_CERT",btemp.s,btemp.len)) return 0;

  if (chain) {
    for (m = 0;m < sk_X509_num(chain);m++) {
      if (!stralloc_copys(&ctemp,"SSL_SERVER_CERT_CHAIN_")) return 0;
      if (!stralloc_catb(&ctemp,strnum,fmt_ulong(strnum,m))) return 0;
      if (!stralloc_0(&ctemp)) return 0;

      if (m < sk_X509_num(chain)) {
	if (!PEM_write_bio_X509(bio,sk_X509_value(chain,m))) return 0;
	n = BIO_pending(bio);
	if (!stralloc_ready(&btemp,n)) return 0;
	btemp.len = n;
	n = BIO_read(bio,btemp.s,n);
	if (n != btemp.len) return 0;
	if (!env_val(ctemp.s,btemp.s,btemp.len)) return 0;
      }
    }
  }

  return 1;
}

static int ssl_server_vars(X509 *cert,STACK_OF(X509) *chain) {
  X509_NAME *xname;
  char *x;
  unsigned long u;
  int n;
  BIO *bio;

  if (!cert) return 1;

  if (!env_val("SSL_SERVER_M_VERSION",strnum,fmt_ulong(strnum,X509_get_version(cert) + 1)))
    return 0;

  u = ASN1_INTEGER_get(X509_get_serialNumber(cert));
  if (!env_val("SSL_SERVER_M_SERIAL",strnum,fmt_ulong(strnum,u)))
    return 0;

  xname = X509_get_subject_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_SERVER_S_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_SERVER_S_DN_C",NID_countryName);
  set_env_id(xname,"SSL_SERVER_S_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_SERVER_S_DN_L",NID_localityName);
  set_env_id(xname,"SSL_SERVER_S_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_SERVER_S_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_SERVER_S_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_SERVER_S_DN_T",NID_title);
  set_env_id(xname,"SSL_SERVER_S_DN_I",NID_initials);
  set_env_id(xname,"SSL_SERVER_S_DN_G",NID_givenName);
  set_env_id(xname,"SSL_SERVER_S_DN_S",NID_surname);
  set_env_id(xname,"SSL_SERVER_S_DN_D",NID_description);
  set_env_id(xname,"SSL_SERVER_S_DN_UID",NID_x500UniqueIdentifier);
  set_env_id(xname,"SSL_SERVER_S_DN_Email",NID_pkcs9_emailAddress);

  xname = X509_get_issuer_name(cert);
  x = X509_NAME_oneline(xname,0,0);
  n = env_str("SSL_SERVER_I_DN",x);
  free(x);
  if (!n) return 0;

  set_env_id(xname,"SSL_SERVER_I_DN_C",NID_countryName);
  set_env_id(xname,"SSL_SERVER_I_DN_ST",NID_stateOrProvinceName);
  set_env_id(xname,"SSL_SERVER_I_DN_L",NID_localityName);
  set_env_id(xname,"SSL_SERVER_I_DN_O",NID_organizationName);
  set_env_id(xname,"SSL_SERVER_I_DN_OU",NID_organizationalUnitName);
  set_env_id(xname,"SSL_SERVER_I_DN_CN",NID_commonName);
  set_env_id(xname,"SSL_SERVER_I_DN_T",NID_title);
  set_env_id(xname,"SSL_SERVER_I_DN_I",NID_initials);
  set_env_id(xname,"SSL_SERVER_I_DN_G",NID_givenName);
  set_env_id(xname,"SSL_SERVER_I_DN_S",NID_surname);
  set_env_id(xname,"SSL_SERVER_I_DN_D",NID_description);
  set_env_id(xname,"SSL_SERVER_I_DN_UID",NID_x500UniqueIdentifier);
  set_env_id(xname,"SSL_SERVER_I_DN_Email",NID_pkcs9_emailAddress);

  n = OBJ_obj2nid(cert->cert_info->signature->algorithm);
  if (!env_str("SSL_SERVER_A_SIG",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  n = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (!env_str("SSL_SERVER_A_KEY",(n == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(n)))
    return 0;

  bio = BIO_new(BIO_s_mem());
  if (!bio) return 0;
  n = ssl_server_bio_vars(cert,chain,bio);
  BIO_free(bio);

  if (!n) return 0;

  return 1;
}

int ssl_client_env(SSL *ssl,stralloc *sa) {
  envsa = sa;
  if (!ssl_session_vars(ssl)) return 0;
  if (!ssl_client_vars(SSL_get_certificate(ssl),0))
    return 0;
  if (!ssl_server_vars(SSL_get_peer_certificate(ssl),SSL_get_peer_cert_chain(ssl)))
    return 0;
  return 1;
}

int ssl_server_env(SSL *ssl,stralloc *sa) {
  envsa = sa;
  if (!ssl_session_vars(ssl)) return 0;
  if (!ssl_server_vars(SSL_get_certificate(ssl),0))
    return 0;
  if (!ssl_client_vars(SSL_get_peer_certificate(ssl),SSL_get_peer_cert_chain(ssl)))
    return 0;
  return 1;
}


