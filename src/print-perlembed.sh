ldopts="`head -1 conf-ldperl`"
runperl="`head -1 conf-perl`"

case "$ldopts" in
  auto)
    ldopts="$runperl -MExtUtils::Embed -e ldopts"
    ;;
esac

echo "$ldopts"
