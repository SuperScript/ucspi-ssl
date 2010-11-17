host=${1-0}
port=${2-443}
args=""
if [ $# -gt 2 ]
then
  shift; shift
  args="$@"
fi
exec HOME/command/sslclient -RHl0 $args -- $host $port TCPBIN/mconnect-io
