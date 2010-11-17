dependon auto-str conf-keyfile
formake './auto-str auto_keyfile "`head -1 conf-keyfile`" > auto_keyfile.c'
./auto-str auto_keyfile "`head -1 conf-keyfile`"
