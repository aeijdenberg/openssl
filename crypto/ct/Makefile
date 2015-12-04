#
# OpenSSL/crypto/ct/Makefile
#

DIR=	ct
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC= ct_b64.c ct_lib.c ctx_lib.c ct_oct.c ct_prn.c ct_vfy.c ct_err.c \
        ct_json.c ct_log.c ct_sct.c
LIBOBJ= ct_b64.o ct_lib.o ctx_lib.o ct_oct.o ct_prn.o ct_vfy.o ct_err.o \
        ct_json.o ct_log.o ct_sct.o

SRC= $(LIBSRC)

HEADER=	ct_lcl.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

errors:
	$(PERL) $(TOP)/util/mkerr.pl -conf ct.ec -hprefix internal/ -write *.c

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update:  depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ct_b64.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_b64.o: ../../include/openssl/asn1.h ../../include/openssl/async.h
ct_b64.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_b64.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_b64.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_b64.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_b64.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_b64.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_b64.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_b64.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_b64.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_b64.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_b64.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
ct_b64.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ct_b64.o: ../../include/openssl/pqueue.h ../../include/openssl/rsa.h
ct_b64.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_b64.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
ct_b64.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl3.h
ct_b64.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_b64.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
ct_b64.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_b64.o: ../../ssl/packet_locl.h ../../ssl/record/record.h
ct_b64.o: ../../ssl/ssl_locl.h ../../ssl/statem/statem.h
ct_b64.o: ../include/internal/cryptlib.h ct_b64.c
ct_err.o: ../../crypto/include/internal/cryptlib.h ../../e_os.h
ct_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_err.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ct_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_err.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_err.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ct_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
ct_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_err.o: ../../include/openssl/x509v3.h ../include/internal/ct_int.h ct_err.c
ct_json.o: ../../crypto/include/internal/cryptlib.h
ct_json.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_json.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_json.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_json.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ct_json.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_json.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_json.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ct_json.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_json.o: ../../include/openssl/ocsp.h ../../include/openssl/opensslconf.h
ct_json.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_json.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ct_json.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ct_json.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ct_json.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_json.o: ct_json.c
ct_lib.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_lib.o: ../../include/openssl/asn1.h ../../include/openssl/async.h
ct_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_lib.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_lib.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_lib.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_lib.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
ct_lib.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ct_lib.o: ../../include/openssl/pqueue.h ../../include/openssl/rsa.h
ct_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_lib.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
ct_lib.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl3.h
ct_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_lib.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
ct_lib.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_lib.o: ../../ssl/packet_locl.h ../../ssl/record/record.h
ct_lib.o: ../../ssl/ssl_locl.h ../../ssl/statem/statem.h
ct_lib.o: ../include/internal/cryptlib.h ct_lib.c
ct_log.o: ../../crypto/include/internal/cryptlib.h
ct_log.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_log.o: ../../include/openssl/asn1.h ../../include/openssl/async.h
ct_log.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_log.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_log.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_log.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_log.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_log.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_log.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_log.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_log.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_log.o: ../../include/openssl/ocsp.h ../../include/openssl/opensslconf.h
ct_log.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_log.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_log.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_log.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_log.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_log.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_log.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_log.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_log.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_log.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_log.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_log.o: ../../ssl/statem/statem.h ct_log.c
ct_oct.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_oct.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_oct.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_oct.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ct_oct.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_oct.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_oct.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ct_oct.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_oct.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_oct.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
ct_oct.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_oct.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_oct.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_oct.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
ct_oct.o: ct_oct.c
ct_prn.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_prn.o: ../../include/openssl/asn1.h ../../include/openssl/async.h
ct_prn.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_prn.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_prn.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_prn.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_prn.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_prn.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_prn.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_prn.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_prn.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_prn.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
ct_prn.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ct_prn.o: ../../include/openssl/pqueue.h ../../include/openssl/rsa.h
ct_prn.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_prn.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
ct_prn.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl3.h
ct_prn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_prn.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
ct_prn.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_prn.o: ../../ssl/packet_locl.h ../../ssl/record/record.h
ct_prn.o: ../../ssl/ssl_locl.h ../../ssl/statem/statem.h
ct_prn.o: ../include/internal/cryptlib.h ct_prn.c
ct_sct.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_sct.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_sct.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_sct.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ct_sct.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_sct.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_sct.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ct_sct.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_sct.o: ../../include/openssl/ocsp.h ../../include/openssl/opensslconf.h
ct_sct.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_sct.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ct_sct.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ct_sct.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_sct.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_sct.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
ct_sct.o: ct_sct.c
ct_vfy.o: ../../crypto/include/internal/ct_int.h ../../e_os.h
ct_vfy.o: ../../include/openssl/asn1.h ../../include/openssl/async.h
ct_vfy.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_vfy.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_vfy.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_vfy.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_vfy.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_vfy.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_vfy.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_vfy.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_vfy.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_vfy.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
ct_vfy.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ct_vfy.o: ../../include/openssl/pqueue.h ../../include/openssl/rsa.h
ct_vfy.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_vfy.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
ct_vfy.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl3.h
ct_vfy.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_vfy.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
ct_vfy.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_vfy.o: ../../ssl/packet_locl.h ../../ssl/record/record.h
ct_vfy.o: ../../ssl/ssl_locl.h ../../ssl/statem/statem.h
ct_vfy.o: ../include/internal/cryptlib.h ct_vfy.c
ctx_lib.o: ../../crypto/include/internal/ct_int.h
ctx_lib.o: ../../crypto/include/internal/x509_int.h ../../e_os.h
ctx_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ctx_lib.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ctx_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ctx_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ctx_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ctx_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ctx_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ctx_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ctx_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
ctx_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ctx_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ctx_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ctx_lib.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
ctx_lib.o: ctx_lib.c
