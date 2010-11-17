dependon auto-str conf-cadir
formake './auto-str auto_cadir "`head -1 conf-cadir`" > auto_cadir.c'
./auto-str auto_cadir "`head -1 conf-cadir`"
