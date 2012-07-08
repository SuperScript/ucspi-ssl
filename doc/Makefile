
default: \
it.www

attribute.conf: \
attribute.conf.build \
../package/name \
../package/path \
../package/versions
	sh makefile.build attribute.conf.build attribute.conf 

environment.html: \
default.html.build \
environment.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build environment.html environment

https@.html: \
default.html.build \
https@.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build https@.html https@

index.html: \
default.html.build \
index.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build index.html index

install.html: \
default.html.build \
install.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build install.html install

it: \
default.build \
it=d \
index.html \
install.html \
sslserver.html \
sslclient.html \
sslcat.html \
sslconnect.html \
https@.html \
prefork.html \
environment.html \
sslperl.html \
UCSPI-SSL
	sh makefile.build default.build it it

it.www: \
default.www.build \
it
	sh makefile.build default.www.build it.www it

mkfile: \
mkfile.build \
mkfile=d \
it
	sh makefile.build mkfile.build mkfile 

prefork.html: \
default.html.build \
prefork.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build prefork.html prefork

sslcat.html: \
default.html.build \
sslcat.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build sslcat.html sslcat

sslclient.html: \
default.html.build \
sslclient.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build sslclient.html sslclient

sslconnect.html: \
default.html.build \
sslconnect.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build sslconnect.html sslconnect

sslperl.html: \
default.html.build \
sslperl.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build sslperl.html sslperl

sslserver.html: \
default.html.build \
sslserver.txt \
asciidoc.conf \
webpage.conf \
attribute.conf
	sh makefile.build default.html.build sslserver.html sslserver
