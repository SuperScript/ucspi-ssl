directtarget
dependon compile ccperl
dependcc $2.c
formake ./compile '`cat ccperl`' $2.c
./compile `cat ccperl` $2.c
