host=${1-0}
shift
port=${2-443}
shift
exec #HOME#/command/sslclient -RHl0 ${1+"$@"} -- "$host" "$port" sh -c 'exec cat <&6'

