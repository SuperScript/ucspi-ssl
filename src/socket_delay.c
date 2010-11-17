#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socket.h"

int socket_tcpnodelay(int s)
{
  int opt = 1;
  return setsockopt(s,IPPROTO_TCP,1,&opt,sizeof opt); /* 1 == TCP_NODELAY */
}
