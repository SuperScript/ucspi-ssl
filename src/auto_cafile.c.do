dependon auto-str conf-cafile
formake './auto-str auto_cafile "`head -1 conf-cafile`" > auto_cafile.c'
./auto-str auto_cafile "`head -1 conf-cafile`"
