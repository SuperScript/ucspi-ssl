#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "byte.h"
#include "socket.h"

int socket_local4(int s,char ip[4],uint16 *port)
{
  struct sockaddr_in sa;
  int dummy = sizeof sa;

  if (getsockname(s,(struct sockaddr *) &sa,&dummy) == -1) return -1;
  byte_copy(ip,4,(char *) &sa.sin_addr);
  uint16_unpack_big((char *) &sa.sin_port,port);
  return 0;
}
