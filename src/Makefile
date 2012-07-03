
default: \
it.command


alloc.o: \
default.o.build \
compile \
alloc.c \
alloc.h \
error.h
	sh makefile.build default.o.build alloc.o alloc

alloc_re.o: \
default.o.build \
compile \
alloc_re.c \
alloc.h \
byte.h
	sh makefile.build default.o.build alloc_re.o alloc_re

auto-str: \
default.build \
auto-str=x \
load \
auto-str.o \
unix.a
	sh makefile.build default.build auto-str auto-str

auto-str.o: \
default.o.build \
compile \
auto-str.c \
buffer.h \
exit.h
	sh makefile.build default.o.build auto-str.o auto-str

auto_cadir.c: \
default.c.build \
auto-str \
conf-cadir
	sh makefile.build default.c.build auto_cadir.c auto_cadir

auto_cadir.o: \
default.o.build \
compile \
auto_cadir.c
	sh makefile.build default.o.build auto_cadir.o auto_cadir

auto_cafile.c: \
default.c.build \
auto-str \
conf-cafile
	sh makefile.build default.c.build auto_cafile.c auto_cafile

auto_cafile.o: \
default.o.build \
compile \
auto_cafile.c
	sh makefile.build default.o.build auto_cafile.o auto_cafile

auto_ccafile.c: \
default.c.build \
auto-str \
conf-ccafile
	sh makefile.build default.c.build auto_ccafile.c auto_ccafile

auto_ccafile.o: \
default.o.build \
compile \
auto_ccafile.c
	sh makefile.build default.o.build auto_ccafile.o auto_ccafile

auto_certfile.c: \
default.c.build \
auto-str \
conf-certfile
	sh makefile.build default.c.build auto_certfile.c auto_certfile

auto_certfile.o: \
default.o.build \
compile \
auto_certfile.c
	sh makefile.build default.o.build auto_certfile.o auto_certfile

auto_ciphers.c: \
default.c.build \
auto-str \
conf-ciphers
	sh makefile.build default.c.build auto_ciphers.c auto_ciphers

auto_ciphers.o: \
default.o.build \
compile \
auto_ciphers.c
	sh makefile.build default.o.build auto_ciphers.o auto_ciphers

auto_dhfile.c: \
default.c.build \
auto-str \
conf-dhfile
	sh makefile.build default.c.build auto_dhfile.c auto_dhfile

auto_dhfile.o: \
default.o.build \
compile \
auto_dhfile.c
	sh makefile.build default.o.build auto_dhfile.o auto_dhfile

auto_keyfile.c: \
default.c.build \
auto-str \
conf-keyfile
	sh makefile.build default.c.build auto_keyfile.c auto_keyfile

auto_keyfile.o: \
default.o.build \
compile \
auto_keyfile.c
	sh makefile.build default.o.build auto_keyfile.o auto_keyfile

buffer.o: \
default.o.build \
compile \
buffer.c \
buffer.h
	sh makefile.build default.o.build buffer.o buffer

buffer_0.o: \
default.o.build \
compile \
buffer_0.c \
buffer.h
	sh makefile.build default.o.build buffer_0.o buffer_0

buffer_1.o: \
default.o.build \
compile \
buffer_1.c \
buffer.h
	sh makefile.build default.o.build buffer_1.o buffer_1

buffer_2.o: \
default.o.build \
compile \
buffer_2.c \
buffer.h
	sh makefile.build default.o.build buffer_2.o buffer_2

buffer_copy.o: \
default.o.build \
compile \
buffer_copy.c \
buffer.h
	sh makefile.build default.o.build buffer_copy.o buffer_copy

buffer_get.o: \
default.o.build \
compile \
buffer_get.c \
buffer.h \
byte.h \
error.h
	sh makefile.build default.o.build buffer_get.o buffer_get

buffer_put.o: \
default.o.build \
compile \
buffer_put.c \
buffer.h \
str.h \
byte.h \
error.h
	sh makefile.build default.o.build buffer_put.o buffer_put

buffer_read.o: \
default.o.build \
compile \
buffer_read.c \
buffer.h
	sh makefile.build default.o.build buffer_read.o buffer_read

buffer_write.o: \
default.o.build \
compile \
buffer_write.c \
buffer.h
	sh makefile.build default.o.build buffer_write.o buffer_write

byte_chr.o: \
default.o.build \
compile \
byte_chr.c \
byte.h
	sh makefile.build default.o.build byte_chr.o byte_chr

byte_copy.o: \
default.o.build \
compile \
byte_copy.c \
byte.h
	sh makefile.build default.o.build byte_copy.o byte_copy

byte_cr.o: \
default.o.build \
compile \
byte_cr.c \
byte.h
	sh makefile.build default.o.build byte_cr.o byte_cr

byte_diff.o: \
default.o.build \
compile \
byte_diff.c \
byte.h
	sh makefile.build default.o.build byte_diff.o byte_diff

byte_zero.o: \
default.o.build \
compile \
byte_zero.c \
byte.h
	sh makefile.build default.o.build byte_zero.o byte_zero

case_diffb.o: \
default.o.build \
compile \
case_diffb.c \
case.h
	sh makefile.build default.o.build case_diffb.o case_diffb

case_diffs.o: \
default.o.build \
compile \
case_diffs.c \
case.h
	sh makefile.build default.o.build case_diffs.o case_diffs

cdb.a: \
default.a.build \
cdb=l \
makelib \
cdb.o \
cdb_hash.o \
cdb_make.o
	sh makefile.build default.a.build cdb.a cdb

cdb.o: \
default.o.build \
compile \
cdb.c \
error.h \
seek.h \
byte.h \
uint32.h \
cdb.h
	sh makefile.build default.o.build cdb.o cdb

cdb_hash.o: \
default.o.build \
compile \
cdb_hash.c \
uint32.h \
cdb.h
	sh makefile.build default.o.build cdb_hash.o cdb_hash

cdb_make.o: \
default.o.build \
compile \
cdb_make.c \
seek.h \
error.h \
alloc.h \
cdb.h \
buffer.h \
uint32.h \
cdb_make.h
	sh makefile.build default.o.build cdb_make.o cdb_make

chkshsgr: \
default.build \
chkshsgr=x \
load \
chkshsgr.o
	sh makefile.build default.build chkshsgr chkshsgr

chkshsgr.o: \
default.o.build \
compile \
chkshsgr.c \
exit.h
	sh makefile.build default.o.build chkshsgr.o chkshsgr

choose: \
default.build \
choose=s \
makeinclude \
makescrip \
warn-auto.sh \
choose.sh
	sh makefile.build default.build choose choose

coe.o: \
default.o.build \
compile \
coe.c \
coe.h
	sh makefile.build default.o.build coe.o coe

compile: \
default.build \
conf-cc \
print-compile.sh \
systype \
warn-auto.sh
	sh makefile.build default.build compile compile

dns_dfd.o: \
default.o.build \
compile \
dns_dfd.c \
error.h \
alloc.h \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_dfd.o dns_dfd

dns_domain.o: \
default.o.build \
compile \
dns_domain.c \
error.h \
alloc.h \
case.h \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_domain.o dns_domain

dns_dtda.o: \
default.o.build \
compile \
dns_dtda.c \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_dtda.o dns_dtda

dns_ip.o: \
default.o.build \
compile \
dns_ip.c \
uint16.h \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_ip.o dns_ip

dns_ipq.o: \
default.o.build \
compile \
dns_ipq.c \
case.h \
byte.h \
str.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_ipq.o dns_ipq

dns_name.o: \
default.o.build \
compile \
dns_name.c \
uint16.h \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_name.o dns_name

dns_nd.o: \
default.o.build \
compile \
dns_nd.c \
byte.h \
fmt.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_nd.o dns_nd

dns_packet.o: \
default.o.build \
compile \
dns_packet.c \
error.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_packet.o dns_packet

dns_random.o: \
default.o.build \
compile \
dns_random.c \
gen_alloc.h \
stralloc.h \
iopause.h \
dns.h \
uint64.h \
tai.h \
taia.h \
uint32.h
	sh makefile.build default.o.build dns_random.o dns_random

dns_rcip.o: \
default.o.build \
compile \
dns_rcip.c \
openreadclose.h \
byte.h \
ip4.h \
env.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_rcip.o dns_rcip

dns_rcrw.o: \
default.o.build \
compile \
dns_rcrw.c \
env.h \
byte.h \
str.h \
openreadclose.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_rcrw.o dns_rcrw

dns_resolve.o: \
default.o.build \
compile \
dns_resolve.c \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_resolve.o dns_resolve

dns_sortip.o: \
default.o.build \
compile \
dns_sortip.c \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_sortip.o dns_sortip

dns_transmit.o: \
default.o.build \
compile \
dns_transmit.c \
socket.h \
alloc.h \
error.h \
byte.h \
uint16.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_transmit.o dns_transmit

dns_txt.o: \
default.o.build \
compile \
dns_txt.c \
uint16.h \
byte.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h
	sh makefile.build default.o.build dns_txt.o dns_txt

env.o: \
default.o.build \
compile \
env.c \
str.h \
env.h
	sh makefile.build default.o.build env.o env

error.o: \
default.o.build \
compile \
error.c \
error.h
	sh makefile.build default.o.build error.o error

error_str.o: \
default.o.build \
compile \
error_str.c \
error.h
	sh makefile.build default.o.build error_str.o error_str

fd_copy.o: \
default.o.build \
compile \
fd_copy.c \
fd.h
	sh makefile.build default.o.build fd_copy.o fd_copy

fd_move.o: \
default.o.build \
compile \
fd_move.c \
fd.h
	sh makefile.build default.o.build fd_move.o fd_move

fmt_ulong.o: \
default.o.build \
compile \
fmt_ulong.c \
fmt.h
	sh makefile.build default.o.build fmt_ulong.o fmt_ulong

getln.o: \
default.o.build \
compile \
getln.c \
byte.h \
buffer.h \
gen_alloc.h \
stralloc.h \
getln.h
	sh makefile.build default.o.build getln.o getln

getln2.o: \
default.o.build \
compile \
getln2.c \
byte.h \
buffer.h \
gen_alloc.h \
stralloc.h \
getln.h
	sh makefile.build default.o.build getln2.o getln2

hasflock.h: \
hasflock.h.build \
choose \
compile \
load \
tryflock.c \
hasflock.h1 \
hasflock.h2
	sh makefile.build hasflock.h.build hasflock.h 

hassgact.h: \
hassgact.h.build \
choose \
compile \
trysgact.c \
hassgact.h1 \
hassgact.h2
	sh makefile.build hassgact.h.build hassgact.h 

hassgprm.h: \
hassgprm.h.build \
choose \
compile \
trysgprm.c \
hassgprm.h1 \
hassgprm.h2
	sh makefile.build hassgprm.h.build hassgprm.h 

hasshsgr.h: \
hasshsgr.h.build \
choose \
compile \
tryshsgr.c \
hasshsgr.h1 \
hasshsgr.h2 \
chkshsgr \
warn-shsgr
	sh makefile.build hasshsgr.h.build hasshsgr.h 

haswaitp.h: \
haswaitp.h.build \
choose \
compile \
load \
trywaitp.c \
haswaitp.h1 \
haswaitp.h2
	sh makefile.build haswaitp.h.build haswaitp.h 

home: \
home.build
	sh makefile.build home.build home 

https@: \
default.build \
https@=s \
makeinclude \
makescrip \
warn-auto.sh \
https@.sh
	sh makefile.build default.build https@ https@

iopause.h: \
iopause.h.build \
choose \
compile \
load \
trypoll.c \
iopause.h1 \
iopause.h2
	sh makefile.build iopause.h.build iopause.h 

iopause.o: \
default.o.build \
compile \
iopause.c \
select.h \
uint64.h \
tai.h \
taia.h \
iopause.h
	sh makefile.build default.o.build iopause.o iopause

ip4_fmt.o: \
default.o.build \
compile \
ip4_fmt.c \
fmt.h \
ip4.h
	sh makefile.build default.o.build ip4_fmt.o ip4_fmt

ip4_scan.o: \
default.o.build \
compile \
ip4_scan.c \
scan.h \
ip4.h
	sh makefile.build default.o.build ip4_scan.o ip4_scan

it: \
default.build \
it=d \
https@ \
sslcat \
sslconnect \
sslclient \
sslserver \
sslprint
	sh makefile.build default.build it it

it.command: \
default.command.build \
it \
it=d
	sh makefile.build default.command.build it.command it

it.install: \
default.install.build \
it.command \
it=d
	sh makefile.build default.install.build it.install it

it.rts: \
default.rts.build \
it.command
	sh makefile.build default.rts.build it.rts it

load: \
default.build \
conf-ld \
print-load.sh \
warn-auto.sh
	sh makefile.build default.build load load

lock_ex.o: \
default.o.build \
compile \
lock_ex.c \
hasflock.h \
lock.h
	sh makefile.build default.o.build lock_ex.o lock_ex

lock_un.o: \
default.o.build \
compile \
lock_un.c \
hasflock.h \
lock.h
	sh makefile.build default.o.build lock_un.o lock_un

makeinclude: \
default.build \
makeinclude.sh \
warn-auto.sh
	sh makefile.build default.build makeinclude makeinclude

makelib: \
default.build \
print-ar.sh \
systype \
warn-auto.sh
	sh makefile.build default.build makelib makelib

makescrip: \
default.build \
warn-auto.sh \
print-makescrip.sh \
conf-scrip \
home
	sh makefile.build default.build makescrip makescrip

mkfile: \
mkfile.build \
mkfile=d \
it.command \
it.rts \
sslperl.command \
sslperl.rts
	sh makefile.build mkfile.build mkfile 

ndelay_off.o: \
default.o.build \
compile \
ndelay_off.c \
ndelay.h
	sh makefile.build default.o.build ndelay_off.o ndelay_off

ndelay_on.o: \
default.o.build \
compile \
ndelay_on.c \
ndelay.h
	sh makefile.build default.o.build ndelay_on.o ndelay_on

open_append.o: \
default.o.build \
compile \
open_append.c \
open.h
	sh makefile.build default.o.build open_append.o open_append

open_read.o: \
default.o.build \
compile \
open_read.c \
open.h
	sh makefile.build default.o.build open_read.o open_read

open_trunc.o: \
default.o.build \
compile \
open_trunc.c \
open.h
	sh makefile.build default.o.build open_trunc.o open_trunc

openreadclose.o: \
default.o.build \
compile \
openreadclose.c \
error.h \
open.h \
readclose.h \
gen_alloc.h \
stralloc.h \
openreadclose.h
	sh makefile.build default.o.build openreadclose.o openreadclose

pathexec_env.o: \
default.o.build \
compile \
pathexec_env.c \
gen_alloc.h \
stralloc.h \
alloc.h \
str.h \
byte.h \
env.h \
pathexec.h
	sh makefile.build default.o.build pathexec_env.o pathexec_env

pathexec_run.o: \
default.o.build \
compile \
pathexec_run.c \
error.h \
gen_alloc.h \
stralloc.h \
str.h \
env.h \
pathexec.h
	sh makefile.build default.o.build pathexec_run.o pathexec_run

perlembed.lib: \
perlembed.lib.build \
conf-perl \
conf-ldperl
	sh makefile.build perlembed.lib.build perlembed.lib 

prot.o: \
default.o.build \
compile \
prot.c \
hasshsgr.h \
prot.h
	sh makefile.build default.o.build prot.o prot

readclose.o: \
default.o.build \
compile \
readclose.c \
error.h \
gen_alloc.h \
stralloc.h \
readclose.h
	sh makefile.build default.o.build readclose.o readclose

remoteinfo.o: \
default.o.build \
compile \
remoteinfo.c \
fmt.h \
buffer.h \
socket.h \
error.h \
uint64.h \
tai.h \
taia.h \
iopause.h \
timeoutconn.h \
gen_alloc.h \
stralloc.h \
uint16.h \
remoteinfo.h
	sh makefile.build default.o.build remoteinfo.o remoteinfo

rules.o: \
default.o.build \
compile \
rules.c \
alloc.h \
open.h \
uint32.h \
cdb.h \
gen_alloc.h \
stralloc.h \
rules.h
	sh makefile.build default.o.build rules.o rules

scan_uint.o: \
default.o.build \
compile \
scan_uint.c \
scan.h
	sh makefile.build default.o.build scan_uint.o scan_uint

scan_ulong.o: \
default.o.build \
compile \
scan_ulong.c \
scan.h
	sh makefile.build default.o.build scan_ulong.o scan_ulong

seek_set.o: \
default.o.build \
compile \
seek_set.c \
seek.h
	sh makefile.build default.o.build seek_set.o seek_set

select.h: \
select.h.build \
choose \
compile \
trysysel.c \
select.h1 \
select.h2
	sh makefile.build select.h.build select.h 

sgetopt.o: \
default.o.build \
compile \
sgetopt.c \
buffer.h \
sgetopt.h \
subgetopt.h
	sh makefile.build default.o.build sgetopt.o sgetopt

sig.o: \
default.o.build \
compile \
sig.c \
sig.h
	sh makefile.build default.o.build sig.o sig

sig_block.o: \
default.o.build \
compile \
sig_block.c \
sig.h \
hassgprm.h
	sh makefile.build default.o.build sig_block.o sig_block

sig_catch.o: \
default.o.build \
compile \
sig_catch.c \
sig.h \
hassgact.h
	sh makefile.build default.o.build sig_catch.o sig_catch

sig_pause.o: \
default.o.build \
compile \
sig_pause.c \
sig.h \
hassgprm.h
	sh makefile.build default.o.build sig_pause.o sig_pause

socket.lib: \
default.lib.build \
trylsock.c \
compile \
load
	sh makefile.build default.lib.build socket.lib socket

socket_accept.o: \
default.o.build \
compile \
socket_accept.c \
byte.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_accept.o socket_accept

socket_bind.o: \
default.o.build \
compile \
socket_bind.c \
byte.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_bind.o socket_bind

socket_conn.o: \
default.o.build \
compile \
socket_conn.c \
byte.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_conn.o socket_conn

socket_delay.o: \
default.o.build \
compile \
socket_delay.c \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_delay.o socket_delay

socket_listen.o: \
default.o.build \
compile \
socket_listen.c \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_listen.o socket_listen

socket_local.o: \
default.o.build \
compile \
socket_local.c \
byte.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_local.o socket_local

socket_opts.o: \
default.o.build \
compile \
socket_opts.c \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_opts.o socket_opts

socket_remote.o: \
default.o.build \
compile \
socket_remote.c \
byte.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_remote.o socket_remote

socket_tcp.o: \
default.o.build \
compile \
socket_tcp.c \
ndelay.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_tcp.o socket_tcp

socket_udp.o: \
default.o.build \
compile \
socket_udp.c \
ndelay.h \
uint16.h \
socket.h
	sh makefile.build default.o.build socket_udp.o socket_udp

ssl.a: \
default.a.build \
ssl=l \
makelib \
ssl.o \
ssl_io.o \
ssl_context.o \
ssl_new.o \
ssl_timeoutconn.o \
ssl_timeoutaccept.o \
ssl_certkey.o \
ssl_ca.o \
ssl_cca.o \
ssl_ciphers.o \
ssl_verify.o \
ssl_params.o \
ssl_error.o \
ssl_env.o
	sh makefile.build default.a.build ssl.a ssl

ssl.o: \
default.o.build \
compile \
ssl.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl.o ssl

ssl_ca.o: \
default.o.build \
compile \
ssl_ca.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_ca.o ssl_ca

ssl_cca.o: \
default.o.build \
compile \
ssl_cca.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_cca.o ssl_cca

ssl_certkey.o: \
default.o.build \
compile \
ssl_certkey.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_certkey.o ssl_certkey

ssl_ciphers.o: \
default.o.build \
compile \
ssl_ciphers.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_ciphers.o ssl_ciphers

ssl_context.o: \
default.o.build \
compile \
ssl_context.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_context.o ssl_context

ssl_env.o: \
default.o.build \
compile \
ssl_env.c \
fmt.h \
pathexec.h \
ssl.h \
gen_alloc.h \
stralloc.h \
str.h
	sh makefile.build default.o.build ssl_env.o ssl_env

ssl_error.o: \
default.o.build \
compile \
ssl_error.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_error.o ssl_error

ssl_io.o: \
default.o.build \
compile \
ssl_io.c \
iopause.h \
buffer.h \
uint64.h \
tai.h \
taia.h \
gen_alloc.h \
stralloc.h \
ssl.h \
error.h
	sh makefile.build default.o.build ssl_io.o ssl_io

ssl_new.o: \
default.o.build \
compile \
ssl_new.c \
gen_alloc.h \
stralloc.h \
ssl.h \
ndelay.h
	sh makefile.build default.o.build ssl_new.o ssl_new

ssl_params.o: \
default.o.build \
compile \
ssl_params.c \
gen_alloc.h \
stralloc.h \
ssl.h
	sh makefile.build default.o.build ssl_params.o ssl_params

ssl_timeoutaccept.o: \
default.o.build \
compile \
ssl_timeoutaccept.c \
gen_alloc.h \
stralloc.h \
ssl.h \
uint64.h \
tai.h \
taia.h \
iopause.h \
error.h
	sh makefile.build default.o.build ssl_timeoutaccept.o ssl_timeoutaccept

ssl_timeoutconn.o: \
default.o.build \
compile \
ssl_timeoutconn.c \
gen_alloc.h \
stralloc.h \
ssl.h \
uint64.h \
tai.h \
taia.h \
iopause.h \
error.h
	sh makefile.build default.o.build ssl_timeoutconn.o ssl_timeoutconn

ssl_verify.o: \
default.o.build \
compile \
ssl_verify.c \
gen_alloc.h \
stralloc.h \
ssl.h \
case.h \
strerr.h
	sh makefile.build default.o.build ssl_verify.o ssl_verify

sslcat: \
default.build \
sslcat=s \
makeinclude \
makescrip \
warn-auto.sh \
sslcat.sh
	sh makefile.build default.build sslcat sslcat

sslclient: \
default.build \
sslclient=x \
load \
sslclient.o \
remoteinfo.o \
timeoutconn.o \
ssl.a \
unix.a \
auto_cafile.o \
auto_cadir.o \
auto_ciphers.o \
socket.lib \
ssl.lib
	sh makefile.build default.build sslclient sslclient

sslclient.o: \
default.o.build \
compile \
sslclient.c \
ssl.h \
sig.h \
exit.h \
subgetopt.h \
sgetopt.h \
fmt.h \
scan.h \
str.h \
ip4.h \
socket.h \
fd.h \
buffer.h \
getln.h \
error.h \
strerr.h \
pathexec.h \
timeoutconn.h \
uint16.h \
remoteinfo.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h \
auto_cafile.h \
auto_cadir.h \
auto_ciphers.h \
byte.h \
ndelay.h \
wait.h
	sh makefile.build default.o.build sslclient.o sslclient

sslconnect: \
default.build \
sslconnect=s \
makeinclude \
makescrip \
warn-auto.sh \
sslconnect.sh
	sh makefile.build default.build sslconnect sslconnect

sslhandle.o: \
default.o.build \
compile \
sslhandle.c \
ssl.h \
str.h \
byte.h \
fmt.h \
scan.h \
ip4.h \
fd.h \
exit.h \
env.h \
prot.h \
open.h \
wait.h \
alloc.h \
buffer.h \
getln.h \
error.h \
strerr.h \
subgetopt.h \
sgetopt.h \
socket.h \
ndelay.h \
uint16.h \
remoteinfo.h \
rules.h \
sig.h \
gen_alloc.h \
stralloc.h \
dns.h \
auto_cafile.h \
auto_cadir.h \
auto_ccafile.h \
auto_dhfile.h \
auto_certfile.h \
auto_keyfile.h \
auto_ciphers.h \
uint64.h \
tai.h \
taia.h \
iopause.h \
coe.h \
lock.h
	sh makefile.build default.o.build sslhandle.o sslhandle

sslperl: \
default.build \
sslperl=x \
load \
sslperl.o \
auto_cafile.o \
auto_ccafile.o \
auto_cadir.o \
auto_dhfile.o \
auto_certfile.o \
auto_keyfile.o \
auto_ciphers.o \
rules.o \
remoteinfo.o \
timeoutconn.o \
sslhandle.o \
cdb.a \
ssl.a \
unix.a \
cdb.a \
unix.a \
socket.lib \
ssl.lib \
socket.lib \
perlembed.lib
	sh makefile.build default.build sslperl sslperl

sslperl.command: \
default.command.build \
sslperl \
sslperl=d
	sh makefile.build default.command.build sslperl.command sslperl

sslperl.install: \
default.install.build \
sslperl.command \
sslperl=d
	sh makefile.build default.install.build sslperl.install sslperl

sslperl.o: \
sslperl.o.build \
compile \
conf-ccperl \
strerr.h \
gen_alloc.h \
stralloc.h \
str.h \
conf-perl
	sh makefile.build sslperl.o.build sslperl.o 

sslperl.rts: \
default.rts.build \
sslperl.command
	sh makefile.build default.rts.build sslperl.rts sslperl

sslprint: \
default.build \
sslprint=x \
load \
sslprint.o \
auto_cafile.o \
auto_ccafile.o \
auto_cadir.o \
auto_dhfile.o \
auto_certfile.o \
auto_keyfile.o \
auto_ciphers.o \
rules.o \
remoteinfo.o \
timeoutconn.o \
sslhandle.o \
cdb.a \
ssl.a \
unix.a \
cdb.a \
unix.a \
socket.lib \
ssl.lib \
socket.lib
	sh makefile.build default.build sslprint sslprint

sslprint.o: \
default.o.build \
compile \
sslprint.c \
buffer.h \
env.h
	sh makefile.build default.o.build sslprint.o sslprint

sslserver: \
default.build \
sslserver=x \
load \
sslserver.o \
auto_cafile.o \
auto_ccafile.o \
auto_cadir.o \
auto_dhfile.o \
auto_certfile.o \
auto_keyfile.o \
auto_ciphers.o \
rules.o \
remoteinfo.o \
timeoutconn.o \
cdb.a \
ssl.a \
unix.a \
socket.lib \
ssl.lib
	sh makefile.build default.build sslserver sslserver

sslserver.o: \
default.o.build \
compile \
sslserver.c \
ssl.h \
str.h \
byte.h \
fmt.h \
scan.h \
ip4.h \
fd.h \
exit.h \
env.h \
prot.h \
open.h \
wait.h \
alloc.h \
buffer.h \
getln.h \
error.h \
strerr.h \
subgetopt.h \
sgetopt.h \
pathexec.h \
socket.h \
ndelay.h \
uint16.h \
remoteinfo.h \
rules.h \
sig.h \
gen_alloc.h \
stralloc.h \
iopause.h \
uint64.h \
tai.h \
taia.h \
dns.h \
auto_cafile.h \
auto_cadir.h \
auto_ccafile.h \
auto_dhfile.h \
auto_certfile.h \
auto_keyfile.h \
auto_ciphers.h
	sh makefile.build default.o.build sslserver.o sslserver

str_chr.o: \
default.o.build \
compile \
str_chr.c \
str.h
	sh makefile.build default.o.build str_chr.o str_chr

str_diff.o: \
default.o.build \
compile \
str_diff.c \
str.h
	sh makefile.build default.o.build str_diff.o str_diff

str_len.o: \
default.o.build \
compile \
str_len.c \
str.h
	sh makefile.build default.o.build str_len.o str_len

str_start.o: \
default.o.build \
compile \
str_start.c \
str.h
	sh makefile.build default.o.build str_start.o str_start

stralloc_cat.o: \
default.o.build \
compile \
stralloc_cat.c \
byte.h \
gen_alloc.h \
stralloc.h
	sh makefile.build default.o.build stralloc_cat.o stralloc_cat

stralloc_catb.o: \
default.o.build \
compile \
stralloc_catb.c \
gen_alloc.h \
stralloc.h \
byte.h
	sh makefile.build default.o.build stralloc_catb.o stralloc_catb

stralloc_cats.o: \
default.o.build \
compile \
stralloc_cats.c \
byte.h \
str.h \
gen_alloc.h \
stralloc.h
	sh makefile.build default.o.build stralloc_cats.o stralloc_cats

stralloc_copy.o: \
default.o.build \
compile \
stralloc_copy.c \
byte.h \
gen_alloc.h \
stralloc.h
	sh makefile.build default.o.build stralloc_copy.o stralloc_copy

stralloc_eady.o: \
default.o.build \
compile \
stralloc_eady.c \
alloc.h \
gen_alloc.h \
stralloc.h \
gen_allocdefs.h
	sh makefile.build default.o.build stralloc_eady.o stralloc_eady

stralloc_opyb.o: \
default.o.build \
compile \
stralloc_opyb.c \
gen_alloc.h \
stralloc.h \
byte.h
	sh makefile.build default.o.build stralloc_opyb.o stralloc_opyb

stralloc_opys.o: \
default.o.build \
compile \
stralloc_opys.c \
byte.h \
str.h \
gen_alloc.h \
stralloc.h
	sh makefile.build default.o.build stralloc_opys.o stralloc_opys

stralloc_pend.o: \
default.o.build \
compile \
stralloc_pend.c \
alloc.h \
gen_alloc.h \
stralloc.h \
gen_allocdefs.h
	sh makefile.build default.o.build stralloc_pend.o stralloc_pend

strerr_die.o: \
default.o.build \
compile \
strerr_die.c \
buffer.h \
exit.h \
strerr.h
	sh makefile.build default.o.build strerr_die.o strerr_die

strerr_sys.o: \
default.o.build \
compile \
strerr_sys.c \
error.h \
strerr.h
	sh makefile.build default.o.build strerr_sys.o strerr_sys

subgetopt.o: \
default.o.build \
compile \
subgetopt.c \
subgetopt.h
	sh makefile.build default.o.build subgetopt.o subgetopt

systype: \
default.build \
find-systype.sh \
trycpp.c \
x86cpuid.c
	sh makefile.build default.build systype systype

tai_pack.o: \
default.o.build \
compile \
tai_pack.c \
uint64.h \
tai.h
	sh makefile.build default.o.build tai_pack.o tai_pack

taia_add.o: \
default.o.build \
compile \
taia_add.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_add.o taia_add

taia_approx.o: \
default.o.build \
compile \
taia_approx.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_approx.o taia_approx

taia_frac.o: \
default.o.build \
compile \
taia_frac.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_frac.o taia_frac

taia_less.o: \
default.o.build \
compile \
taia_less.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_less.o taia_less

taia_now.o: \
default.o.build \
compile \
taia_now.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_now.o taia_now

taia_pack.o: \
default.o.build \
compile \
taia_pack.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_pack.o taia_pack

taia_sub.o: \
default.o.build \
compile \
taia_sub.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_sub.o taia_sub

taia_uint.o: \
default.o.build \
compile \
taia_uint.c \
uint64.h \
tai.h \
taia.h
	sh makefile.build default.o.build taia_uint.o taia_uint

timeoutconn.o: \
default.o.build \
compile \
timeoutconn.c \
ndelay.h \
socket.h \
uint64.h \
tai.h \
taia.h \
iopause.h \
error.h \
uint16.h \
timeoutconn.h
	sh makefile.build default.o.build timeoutconn.o timeoutconn

uint16_pack.o: \
default.o.build \
compile \
uint16_pack.c \
uint16.h
	sh makefile.build default.o.build uint16_pack.o uint16_pack

uint16_unpack.o: \
default.o.build \
compile \
uint16_unpack.c \
uint16.h
	sh makefile.build default.o.build uint16_unpack.o uint16_unpack

uint32.h: \
uint32.h.build \
choose \
compile \
load \
tryulong32.c \
uint32.h1 \
uint32.h2
	sh makefile.build uint32.h.build uint32.h 

uint32_pack.o: \
default.o.build \
compile \
uint32_pack.c \
uint32.h
	sh makefile.build default.o.build uint32_pack.o uint32_pack

uint32_unpack.o: \
default.o.build \
compile \
uint32_unpack.c \
uint32.h
	sh makefile.build default.o.build uint32_unpack.o uint32_unpack

uint64.h: \
uint64.h.build \
choose \
compile \
load \
tryulong64.c \
uint64.h1 \
uint64.h2
	sh makefile.build uint64.h.build uint64.h 

unix.a: \
default.a.build \
unix=l \
makelib \
alloc.o \
alloc_re.o \
buffer.o \
buffer_0.o \
buffer_1.o \
buffer_2.o \
buffer_get.o \
buffer_put.o \
buffer_copy.o \
buffer_read.o \
buffer_write.o \
env.o \
error.o \
error_str.o \
fd_copy.o \
fd_move.o \
fmt_ulong.o \
getln.o \
getln2.o \
socket_accept.o \
socket_bind.o \
socket_conn.o \
socket_delay.o \
socket_listen.o \
socket_local.o \
socket_opts.o \
socket_remote.o \
socket_tcp.o \
socket_udp.o \
ndelay_on.o \
ndelay_off.o \
open_append.o \
open_read.o \
open_trunc.o \
openreadclose.o \
pathexec_env.o \
pathexec_run.o \
prot.o \
readclose.o \
seek_set.o \
sgetopt.o \
sig.o \
sig_block.o \
sig_catch.o \
sig_pause.o \
str_chr.o \
str_diff.o \
str_len.o \
str_start.o \
stralloc_cat.o \
stralloc_catb.o \
stralloc_cats.o \
stralloc_copy.o \
stralloc_eady.o \
stralloc_opyb.o \
stralloc_opys.o \
stralloc_pend.o \
strerr_die.o \
strerr_sys.o \
subgetopt.o \
wait_nohang.o \
wait_pid.o \
byte_chr.o \
byte_copy.o \
byte_cr.o \
byte_diff.o \
byte_zero.o \
case_diffb.o \
case_diffs.o \
ip4_fmt.o \
ip4_scan.o \
scan_ulong.o \
scan_uint.o \
uint16_pack.o \
uint16_unpack.o \
uint32_pack.o \
uint32_unpack.o \
iopause.o \
tai_pack.o \
taia_add.o \
taia_approx.o \
taia_frac.o \
taia_less.o \
taia_now.o \
taia_pack.o \
taia_sub.o \
taia_uint.o \
dns_dfd.o \
dns_domain.o \
dns_dtda.o \
dns_ip.o \
dns_ipq.o \
dns_name.o \
dns_nd.o \
dns_packet.o \
dns_random.o \
dns_rcip.o \
dns_rcrw.o \
dns_resolve.o \
dns_sortip.o \
dns_transmit.o \
dns_txt.o \
lock_ex.o \
lock_un.o \
coe.o
	sh makefile.build default.a.build unix.a unix

wait_nohang.o: \
default.o.build \
compile \
wait_nohang.c \
haswaitp.h
	sh makefile.build default.o.build wait_nohang.o wait_nohang

wait_pid.o: \
default.o.build \
compile \
wait_pid.c \
error.h \
haswaitp.h
	sh makefile.build default.o.build wait_pid.o wait_pid
