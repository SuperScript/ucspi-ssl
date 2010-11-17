ccopts="`head -1 conf-ccperl`"
runperl="`head -1 conf-perl`"

case "$ccopts" in
  auto)
    ccopts="`$runperl -MExtUtils::Embed -e ccopts`"
    ;;
esac

echo "$ccopts"
