dependon prog rts rts.tests rts.exp \
ucspi.ca 127.0.0.1.cert 127.0.0.1.key 127.0.0.1.pw \
localhost.cert localhost.key localhost.pw
formake './rts | cmp - rts.exp'
./rts | cmp - rts.exp
directtarget

