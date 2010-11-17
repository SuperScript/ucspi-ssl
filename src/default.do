if test -r $1=x
then
  dependon $1=x
  libs=`grep '\.lib *$' "$1=x" || exit 0`
  libscat=''
  for i in $libs
  do
    libscat="$libscat "'`'"cat $i"'`'
  done
  objs=`grep -v '\.lib *$' "$1=x" || exit 0`
  dependon load $1.o $objs $libs
  directtarget
  formake ./load $1 $objs "$libscat"
  eval ./load $1 $objs $libscat
  exit 0
fi

if test -r $1=s
then
  dependon $1=s makeinclude makescrip
  scripts=`cat $1=s`
  if [ "X$scripts" = "X" ]
  then
    scripts="warn-auto.sh $1.sh"
  fi
  dependon `./makeinclude deps $scripts`
  formake rm -f $1
  formake ./makeinclude code $scripts '\'
  formake '| ./makescrip' "$@" '\'
  formake '>' $1
  formake chmod 755 $1
  rm -f $1
  ./makeinclude code $scripts \
  | ./makescrip "$@"
  chmod 755 $3
  exit 0
fi

case $1 in
  compile)
    dependon conf-cc print-cc.sh systype warn-auto.sh
    formake rm -f compile
    formake 'sh print-cc.sh > compile'
    formake "chmod 755 compile"
    rm -f compile
    sh print-cc.sh
    chmod 755 $3
    exit 0
    ;;
  it)
    dependon $1=d sysdeps
    dependon `awk '{ print $1; }' <$1=d`
    directtarget
    exit 0
    ;;
  load)
    dependon conf-ld print-ld.sh systype warn-auto.sh
    formake rm -f load
    formake 'sh print-ld.sh > load'
    formake "chmod 755 load"
    rm -f load
    sh print-ld.sh
    chmod 755 $3
    exit 0
    ;;
  loads)
    dependon conf-lds print-lds.sh systype warn-auto.sh
    formake rm -f loads
    formake 'sh print-lds.sh > loads'
    formake "chmod 755 loads"
    rm -f loads
    sh print-lds.sh
    chmod 755 $3
    exit 0
    ;;
  makelib)
    dependon print-ar.sh systype warn-auto.sh
    formake rm -f makelib
    formake 'sh print-ar.sh > makelib'
    formake "chmod 755 makelib"
    rm -f makelib
    sh print-ar.sh
    chmod 755 $3
    exit 0
    ;;
  makeinclude)
    dependon makeinclude.sh warn-auto.sh
    formake rm -f makeinclude
    formake 'cat warn-auto.sh makeinclude.sh > makeinclude'
    formake "chmod 755 makeinclude"
    rm -f makeinclude
    cat warn-auto.sh makeinclude.sh
    chmod 755 $3
    exit 0
    ;;
  makescrip)
    dependon warn-auto.sh print-makescrip.sh conf-scrip
    dependon `sed -e '/^$/q' -e '/^dep#/!d' -e 's/^dep#//' < conf-scrip`
    formake rm -f makescrip
    formake 'sh print-makescrip.sh < conf-scrip > makescrip'
    formake "chmod 755 makescrip"
    rm -f makescrip
    sh print-makescrip.sh < conf-scrip
    chmod 755 $3
    exit 0
    ;;
  sysdeps)
    dependon systype compile load `grep -l sysdep *.h 2>/dev/null || exit 0`
    formake 'rm -f sysdeps'
    formake 'cat systype compile load >> sysdeps'
    formake 'grep sysdep *.h 2>/dev/null >> sysdeps || :'
    rm -f sysdeps
    cat systype compile load
    grep sysdep *.h 2>/dev/null || :
    exit 0
    ;;
  systype)
    dependon find-systype.sh trycpp.c x86cpuid.c
    formake 'sh find-systype.sh > systype'
    sh find-systype.sh
    exit 0
    ;;
esac

nosuchtarget
