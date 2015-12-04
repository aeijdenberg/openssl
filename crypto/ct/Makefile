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
LIBSRC= ct_lib.c ct_err.c ct_oct.c ct_prn.c
LIBOBJ= ct_lib.o ct_err.o ct_oct.o ct_prn.o

SRC= $(LIBSRC)

HEADER=	

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
ct_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ct_lib.o: ../../include/openssl/async.h ../../include/openssl/bio.h
ct_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ct_lib.o: ../../include/openssl/comp.h ../../include/openssl/conf.h
ct_lib.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
ct_lib.o: ../../include/openssl/dtls1.h ../../include/openssl/e_os2.h
ct_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_lib.o: ../../include/openssl/evp.h ../../include/openssl/hmac.h
ct_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
ct_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_lib.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_lib.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_lib.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_lib.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_lib.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_lib.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_lib.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_lib.o: ../../ssl/statem/statem.h ../include/internal/cryptlib.h
ct_lib.o: ../include/internal/ct_int.h ct_lib.c
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
ct_prn.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_prn.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_prn.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ct_prn.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ct_prn.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ct_prn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ct_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_prn.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_prn.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
ct_prn.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_prn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_prn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_prn.o: ../../include/openssl/x509v3.h ../include/internal/cryptlib.h
ct_prn.o: ct_prn.c
