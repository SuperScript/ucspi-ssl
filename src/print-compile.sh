cc="`head -1 conf-cc`"
if [ "$cc" = "auto" ]
then
  auto="auto"
  extra="`awk '2 == NR { print; exit }' < conf-cc`"
else
  auto="manual"
  extra=""
fi

systype="`cat systype`"


gcc -c trycpp.c -malign-double >/dev/null 2>&1 \
&& gccad="-malign-double"

gcc -c trycpp.c -mcpu=ultrasparc >/dev/null 2>&1 \
&& gccus="-mcpu=ultrasparc"

gcc -c trycpp.c -mcpu=powerpc >/dev/null 2>&1 \
&& gccpp="-mcpu=powerpc"

gcc -c trycpp.c -mcpu=21164 >/dev/null 2>&1 \
&& gcc21="-mcpu=21164"

rm -f trycpp.o


gccbase="gcc -fomit-frame-pointer -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings"


case "$auto:$systype" in
  auto:*:i386-*:*)
    cc="$gccbase -O1 $gccad"
    ;;
  auto:*:sparc-*:*:*:*)
    cc="$gccbase -O1 $gccus"
    ;;
  auto:*:ppc-*:*:*:*)
    cc="$gccbase -O2 $gccpp"
    ;;
  auto:*:alpha-*:*:*:*)
    cc="$gccbase -O2 $gcc21"
    ;;
  auto:aix-*:-:-:*:-)
    cc="$gccbase -O2 $gccpp"
    ;;
  auto:*)
    cc="$gccbase -O2"
    ;;
esac


cat warn-auto.sh
echo exec "$cc" "$extra" '-c -o ${1+"$@"}'
