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

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ct_b64.o: ../../crypto/ct/ct_locl.h ../../e_os.h ../../include/openssl/asn1.h
ct_b64.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_b64.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_b64.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_b64.o: ../../include/openssl/ct.h ../../include/openssl/dsa.h
ct_b64.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
ct_b64.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_b64.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_b64.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
ct_b64.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_b64.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ct_b64.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_b64.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_b64.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_b64.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_b64.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_b64.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_b64.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_b64.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_b64.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_b64.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_b64.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_b64.o: ../include/internal/cryptlib.h ct_b64.c ct_locl.h
ct_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ct_err.o: ../../include/openssl/ct.h ../../include/openssl/e_os2.h
ct_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_err.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_err.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ct_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
ct_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_err.o: ct_err.c
ct_json.o: ../../crypto/ct/ct_locl.h ../../include/openssl/asn1.h
ct_json.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
ct_json.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_json.o: ../../include/openssl/ct.h ../../include/openssl/e_os2.h
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
ct_lib.o: ../../crypto/ct/ct_locl.h ../../e_os.h ../../include/openssl/asn1.h
ct_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_lib.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_lib.o: ../../include/openssl/crypto.h ../../include/openssl/ct.h
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
ct_lib.o: ../../include/openssl/x509_vfy.h ../../ssl/packet_locl.h
ct_lib.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_lib.o: ../include/internal/cryptlib.h ct_lib.c ct_locl.h
ct_log.o: ../../crypto/ct/ct_locl.h ../../e_os.h ../../include/openssl/asn1.h
ct_log.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_log.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_log.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_log.o: ../../include/openssl/ct.h ../../include/openssl/dsa.h
ct_log.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
ct_log.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_log.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_log.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
ct_log.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_log.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ct_log.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_log.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
ct_log.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
ct_log.o: ../../include/openssl/pqueue.h ../../include/openssl/rsa.h
ct_log.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_log.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
ct_log.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl3.h
ct_log.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_log.o: ../../include/openssl/tls1.h ../../include/openssl/x509.h
ct_log.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_log.o: ../../ssl/packet_locl.h ../../ssl/record/record.h
ct_log.o: ../../ssl/ssl_locl.h ../include/internal/cryptlib.h ct_log.c
ct_oct.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_oct.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_oct.o: ../../include/openssl/crypto.h ../../include/openssl/ct.h
ct_oct.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_oct.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_oct.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_oct.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_oct.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ct_oct.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_oct.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ct_oct.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ct_oct.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ct_oct.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
ct_oct.o: ../include/internal/cryptlib.h ct_locl.h ct_oct.c
ct_prn.o: ../../crypto/ct/ct_locl.h ../../e_os.h ../../include/openssl/asn1.h
ct_prn.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_prn.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_prn.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_prn.o: ../../include/openssl/ct.h ../../include/openssl/dsa.h
ct_prn.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
ct_prn.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_prn.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_prn.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
ct_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_prn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ct_prn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_prn.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_prn.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_prn.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_prn.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_prn.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_prn.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_prn.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_prn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_prn.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_prn.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_prn.o: ../include/internal/cryptlib.h ct_locl.h ct_prn.c
ct_sct.o: ../../crypto/ct/ct_locl.h ../../e_os.h ../../include/openssl/asn1.h
ct_sct.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
ct_sct.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_sct.o: ../../include/openssl/ct.h ../../include/openssl/e_os2.h
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
ct_vfy.o: ../../crypto/ct/ct_locl.h ../../e_os.h ../../include/openssl/asn1.h
ct_vfy.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ct_vfy.o: ../../include/openssl/buffer.h ../../include/openssl/comp.h
ct_vfy.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ct_vfy.o: ../../include/openssl/ct.h ../../include/openssl/dsa.h
ct_vfy.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
ct_vfy.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_vfy.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_vfy.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
ct_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_vfy.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ct_vfy.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_vfy.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_vfy.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_vfy.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_vfy.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_vfy.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_vfy.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_vfy.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_vfy.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_vfy.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_vfy.o: ../include/internal/cryptlib.h ct_locl.h ct_vfy.c
ctx_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ctx_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
ctx_lib.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
ctx_lib.o: ../../include/openssl/ct.h ../../include/openssl/e_os2.h
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
ctx_lib.o: ct_locl.h ctx_lib.c
