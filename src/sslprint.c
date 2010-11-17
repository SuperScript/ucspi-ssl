#include "buffer.h"
#include "env.h"

static char *e[] = {0};
static int n = 0;

void server(int argc,const char * const *argv) {
  char *x;

  buffer_puts(buffer_1,"\nPROTO=");
  x = env_get("PROTO");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLLOCALHOST=");
  x = env_get("SSLLOCALHOST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLLOCALIP=");
  x = env_get("SSLLOCALIP"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLLOCALPORT=");
  x = env_get("SSLLOCALPORT"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLREMOTEHOST=");
  x = env_get("SSLREMOTEHOST"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLREMOTEIP=");
  x = env_get("SSLREMOTEIP"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLREMOTEPORT=");
  x = env_get("SSLREMOTEPORT"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSLREMOTEINFO=");
  x = env_get("SSLREMOTEINFO"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPLOCALHOST=");
  x = env_get("TCPLOCALHOST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPLOCALIP=");
  x = env_get("TCPLOCALIP"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPLOCALPORT=");
  x = env_get("TCPLOCALPORT"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEHOST=");
  x = env_get("TCPREMOTEHOST"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEIP=");
  x = env_get("TCPREMOTEIP"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEPORT=");
  x = env_get("TCPREMOTEPORT"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nTCPREMOTEINFO=");
  x = env_get("TCPREMOTEINFO"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_PROTOCOL=");
  x = env_get("SSL_PROTOCOL");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SESSION_ID=");
  x = env_get("SSL_SESSION_ID");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CIPHER=");
  x = env_get("SSL_CIPHER");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CIPHER_EXPORT=");
  x = env_get("SSL_CIPHER_EXPORT");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CIPHER_USEKEYSIZE=");
  x = env_get("SSL_CIPHER_USEKEYSIZE");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CIPHER_ALGKEYSIZE=");
  x = env_get("SSL_CIPHER_ALGKEYSIZE");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_VERSION_INTERFACE=");
  x = env_get("SSL_VERSION_INTERFACE");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_VERSION_LIBRARY=");
  x = env_get("SSL_VERSION_LIBRARY");
  buffer_puts(buffer_1,x ? x : "unset");


  buffer_puts(buffer_1,"\nSSL_SERVER_M_VERSION=");
  x = env_get("SSL_SERVER_M_VERSION");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_M_SERIAL=");
  x = env_get("SSL_SERVER_M_SERIAL");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN=");
  x = env_get("SSL_SERVER_S_DN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_C=");
  x = env_get("SSL_SERVER_S_DN_C");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_ST=");
  x = env_get("SSL_SERVER_S_DN_ST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_L=");
  x = env_get("SSL_SERVER_S_DN_L");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_O=");
  x = env_get("SSL_SERVER_S_DN_O");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_OU=");
  x = env_get("SSL_SERVER_S_DN_OU");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_CN=");
  x = env_get("SSL_SERVER_S_DN_CN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_T=");
  x = env_get("SSL_SERVER_S_DN_T");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_I=");
  x = env_get("SSL_SERVER_S_DN_I");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_G=");
  x = env_get("SSL_SERVER_S_DN_G");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_S=");
  x = env_get("SSL_SERVER_S_DN_S");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_D=");
  x = env_get("SSL_SERVER_S_DN_D");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_UID=");
  x = env_get("SSL_SERVER_S_DN_UID");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_S_DN_Email=");
  x = env_get("SSL_SERVER_S_DN_Email");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN=");
  x = env_get("SSL_SERVER_I_DN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_C=");
  x = env_get("SSL_SERVER_I_DN_C");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_ST=");
  x = env_get("SSL_SERVER_I_DN_ST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_L=");
  x = env_get("SSL_SERVER_I_DN_L");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_O=");
  x = env_get("SSL_SERVER_I_DN_O");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_OU=");
  x = env_get("SSL_SERVER_I_DN_OU");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_CN=");
  x = env_get("SSL_SERVER_I_DN_CN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_T=");
  x = env_get("SSL_SERVER_I_DN_T");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_I=");
  x = env_get("SSL_SERVER_I_DN_I");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_G=");
  x = env_get("SSL_SERVER_I_DN_G");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_S=");
  x = env_get("SSL_SERVER_I_DN_S");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_D=");
  x = env_get("SSL_SERVER_I_DN_D");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_UID=");
  x = env_get("SSL_SERVER_I_DN_UID");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_I_DN_Email=");
  x = env_get("SSL_SERVER_I_DN_Email");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_V_START=");
  x = env_get("SSL_SERVER_V_START");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_V_END=");
  x = env_get("SSL_SERVER_V_END");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_A_SIG=");
  x = env_get("SSL_SERVER_A_SIG");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_A_KEY=");
  x = env_get("SSL_SERVER_A_KEY");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_SERVER_CERT=");
  x = env_get("SSL_SERVER_CERT");
  buffer_puts(buffer_1,x ? x : "unset");


  buffer_puts(buffer_1,"\nSSL_CLIENT_M_VERSION=");
  x = env_get("SSL_CLIENT_M_VERSION");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_M_SERIAL=");
  x = env_get("SSL_CLIENT_M_SERIAL");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN=");
  x = env_get("SSL_CLIENT_S_DN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_C=");
  x = env_get("SSL_CLIENT_S_DN_C");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_ST=");
  x = env_get("SSL_CLIENT_S_DN_ST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_L=");
  x = env_get("SSL_CLIENT_S_DN_L");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_O=");
  x = env_get("SSL_CLIENT_S_DN_O");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_OU=");
  x = env_get("SSL_CLIENT_S_DN_OU");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_CN=");
  x = env_get("SSL_CLIENT_S_DN_CN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_T=");
  x = env_get("SSL_CLIENT_S_DN_T");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_I=");
  x = env_get("SSL_CLIENT_S_DN_I");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_G=");
  x = env_get("SSL_CLIENT_S_DN_G");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_S=");
  x = env_get("SSL_CLIENT_S_DN_S");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_D=");
  x = env_get("SSL_CLIENT_S_DN_D");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_UID=");
  x = env_get("SSL_CLIENT_S_DN_UID");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_S_DN_Email=");
  x = env_get("SSL_CLIENT_S_DN_Email");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN=");
  x = env_get("SSL_CLIENT_I_DN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_C=");
  x = env_get("SSL_CLIENT_I_DN_C");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_ST=");
  x = env_get("SSL_CLIENT_I_DN_ST");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_L=");
  x = env_get("SSL_CLIENT_I_DN_L");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_O=");
  x = env_get("SSL_CLIENT_I_DN_O");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_OU=");
  x = env_get("SSL_CLIENT_I_DN_OU");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_CN=");
  x = env_get("SSL_CLIENT_I_DN_CN");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_T=");
  x = env_get("SSL_CLIENT_I_DN_T");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_I=");
  x = env_get("SSL_CLIENT_I_DN_I");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_G=");
  x = env_get("SSL_CLIENT_I_DN_G");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_S=");
  x = env_get("SSL_CLIENT_I_DN_S");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_D=");
  x = env_get("SSL_CLIENT_I_DN_D");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_UID=");
  x = env_get("SSL_CLIENT_I_DN_UID");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_I_DN_Email=");
  x = env_get("SSL_CLIENT_I_DN_Email");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_V_START=");
  x = env_get("SSL_CLIENT_V_START");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_V_END=");
  x = env_get("SSL_CLIENT_V_END");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_A_SIG=");
  x = env_get("SSL_CLIENT_A_SIG");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_A_KEY=");
  x = env_get("SSL_CLIENT_A_KEY");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_CERT=");
  x = env_get("SSL_CLIENT_CERT");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_CERT_CHAIN_0=");
  x = env_get("SSL_CLIENT_CERT_CHAIN_0");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nSSL_CLIENT_CERT_CHAIN_1=");
  x = env_get("SSL_CLIENT_CERT_CHAIN_1");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_putsflush(buffer_1,"\n");

  if (++n > 1) {
    environ = e;
  }
}
