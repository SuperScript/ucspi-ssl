dependon auto-str conf-ccafile
formake './auto-str auto_ccafile "`head -1 conf-ccafile`" > auto_ccafile.c'
./auto-str auto_ccafile "`head -1 conf-ccafile`"
