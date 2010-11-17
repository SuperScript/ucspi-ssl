case $1 in
  socket.lib)
    dependon trylsock.c compile load
    formake '( ( ./compile trylsock.c && \'
    formake './load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \'
    formake '&& echo -lsocket -lnsl || exit 0 ) > socket.lib'
    formake 'rm -f trylsock.o trylsock'
    ( ( ./compile trylsock.c && \
      ./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
      && echo -lsocket -lnsl || exit 0 )
      rm -f trylsock.o trylsock
    exit 0
    ;;
  dns.lib)
    dependon tryrsolv.c compile load socket.lib
    formake '( ( ./compile tryrsolv.c && ./load tryrsolv \'
    formake '-lresolv `cat socket.lib` ) >/dev/null 2>&1 \'
    formake '&& echo -lresolv || exit 0 ) > dns.lib'
    formake 'rm -f tryrsolv.o tryrsolv'
    ( ( ./compile tryrsolv.c && ./load tryrsolv \
      -lresolv `cat socket.lib` ) >/dev/null 2>&1 \
      && echo -lresolv || exit 0 )
      rm -f tryrsolv.o tryrsolv
    exit 0
    ;;
esac
nosuchtarget
