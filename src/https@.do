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
formake '| sed s}TCPBIN}"`head -1 conf-tcpbin`"}g \'
formake '>' $1
formake chmod 755 $1
rm -f $1
cat $scripts \
| sed s}HOME}"`head -1 home`"}g \
| sed s}TCPBIN}"`head -1 conf-tcpbin`"}g
chmod 755 $3
exit 0
