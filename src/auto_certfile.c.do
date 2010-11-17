dependon auto-str conf-certfile
formake './auto-str auto_certfile "`head -1 conf-certfile`" > auto_certfile.c'
./auto-str auto_certfile "`head -1 conf-certfile`"
