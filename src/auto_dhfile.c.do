dependon auto-str conf-dhfile
formake './auto-str auto_dhfile "`head -1 conf-dhfile`" > auto_dhfile.c'
./auto-str auto_dhfile "`head -1 conf-dhfile`"
