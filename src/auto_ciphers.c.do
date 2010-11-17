dependon auto-str conf-ciphers
formake './auto-str auto_ciphers "`head -1 conf-ciphers`" > auto_ciphers.c'
./auto-str auto_ciphers "`head -1 conf-ciphers`"
