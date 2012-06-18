# makeinclude mode file ...
# For mode deps, print #include'd file names
# For mode code, print code and #include'd code
# 
awk=`{ which gawk >/dev/null && echo gawk; } \
  || { which nawk >/dev/null && echo nawk; } \
  || echo awk`
exec $awk '
function shout(msg) { print "makeinclude: " msg | "cat - 1>&2"; }
function barf(msg) { shout("fatal: " msg); exit 111; }
function dofile(fname,  i,x,a) {
  if (1 == included[fname]) return
  if (deps) print fname
  included[fname] = 1
  i = 0
  while (1) {
    r = getline x <fname
    if (0 > r) barf("cannot open file: " fname)
    if (0 == r) break
    line[i++,fname] = x;
  }
  close(fname)
  pos[fname] = 0
  lim[fname] = i
  while (pos[fname] < lim[fname]) {
    x = line[pos[fname]++,fname]
    if (x ~ /^#include[ \t]*"[^"]*"/) {
      split(x,a,"\"")
      dofile(a[2])
    }
    else {
      if (!deps) print x
    }
  }
}
BEGIN {
  mode = ARGV[1]
  ARGV[1] = ""
  mode ~ /^(deps|code)$/  || barf("unrecognized mode: " mode)
  deps = ("deps" == mode ? 1 : 0)
  for (i = 2;i < ARGC;++i) {
    dofile(ARGV[i]);
  }
  exit 0
}
{ barf("this should never happen") }
' ${1+"$@"}

