dependon choose compile tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr warn-shsgr
formake './chkshsgr || ( cat warn-shsgr; exit 1 )'
formake './choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h'
./chkshsgr || ( cat warn-shsgr; exit 1; )
./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2
