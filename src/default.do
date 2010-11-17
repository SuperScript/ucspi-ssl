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
  dependon $1=s home
  scripts=`cat $1=s`
  if test "X$scripts" = "X"
  then
    scripts="warn-auto.sh $1.sh"
  fi
  dependon $scripts
  formake rm -f $1
  formake cat $scripts '\'
  formake '| sed s}HOME}"`head -1 home`"}g \'
  formake '>' $1
  formake chmod 755 $1
  rm -f $1
  cat $scripts \
  | sed s}HOME}"`head -1 home`"}g
  chmod 755 $3
  exit 0
fi

case $1 in
  compile)
    dependon conf-cc conf-ssl print-cc.sh systype warn-auto.sh
    formake rm -f compile
    formake 'sh print-cc.sh > compile'
    formake "chmod 755 compile"
    rm -f compile
    sh print-cc.sh
    chmod 755 $3
    exit 0
    ;;
  it|it-*)
    dependon $1=d `cat $1=d` sysdeps
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
  sysdeps)
    dependon systype compile load `grep -l sysdep *.h || exit 0`
    formake 'rm -f sysdeps'
    formake 'cat systype compile load >> sysdeps'
    for i in `grep -l sysdep *.h || exit 0`
    do
      formake "grep sysdep $i >> sysdeps"
    done
    rm -f sysdeps
    cat systype compile load
    for i in `grep -l sysdep *.h || exit 0`
    do
      grep sysdep $i
    done
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
