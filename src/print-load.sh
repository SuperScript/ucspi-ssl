ld="`head -1 conf-ld`"

cat warn-auto.sh
echo 'output="$1"; shift'
echo 'main="$1"; shift'
echo exec "$ld" '-o "$output" "$main".o ${1+"$@"}'
