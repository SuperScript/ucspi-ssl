cat warn-auto.sh
exec awk '
BEGIN {
  FS = "#"
  lim = 0
}
/^$/ { exit 0 }
"dep" == $1 { next }
"var" == $1 {
  cmd[++lim] = "-e \047s^\043" $2 "\043^\047" $3 "\047^g\047"
}
{ next }
END {
  if (0 == lim) {
    print "exec cat -"
  }
  else {
    print "exec sed \\"
    for(j = 1;j < lim;++j) {
      print cmd[j] " \\"
    }
    print cmd[lim]
  }
}
'
