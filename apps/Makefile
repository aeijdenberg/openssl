#
#  apps/Makefile
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../crypto -I../include
CFLAG=		-g -static -Wswitch
MAKEFILE=	Makefile
PERL=		perl
RM=		rm -f

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

SHLIB_TARGET=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile makeapps.com install.com

DLIBCRYPTO=../libcrypto.a
DLIBSSL=../libssl.a
LIBCRYPTO=-L.. -lcrypto
LIBSSL=-L.. -lssl

SCRIPTS=CA.pl tsget
EXE= openssl$(EXE_EXT)

COMMANDS= \
	asn1pars.o ca.o ciphers.o cms.o crl.o crl2p7.o dgst.o dhparam.o \
	dsa.o dsaparam.o ec.o ecparam.o enc.o engine.o errstr.o gendsa.o \
	genpkey.o genrsa.o nseq.o ocsp.o passwd.o pkcs12.o pkcs7.o pkcs8.o \
	pkey.o pkeyparam.o pkeyutl.o prime.o rand.o req.o rsa.o rsautl.o \
	s_client.o s_server.o s_time.o sess_id.o smime.o speed.o spkac.o \
	srp.o ts.o verify.o version.o x509.o rehash.o ct.o

EXTRA_OBJ=apps.o opt.o s_cb.o s_socket.o
EXTRA_SRC=apps.c opt.c s_cb.c s_socket.c
RAND_OBJ=app_rand.o
RAND_SRC=app_rand.c

OBJ	= $(COMMANDS)

SRC	= \
	asn1pars.c ca.c ciphers.c cms.c crl.c crl2p7.c dgst.c dhparam.c \
	dsa.c dsaparam.c ec.c ecparam.c enc.c engine.c errstr.c gendsa.c \
	genpkey.c genrsa.c nseq.c ocsp.c passwd.c pkcs12.c pkcs7.c pkcs8.c \
	pkey.c pkeyparam.c pkeyutl.c prime.c rand.c req.c rsa.c rsautl.c \
	s_client.c s_server.c s_time.c sess_id.c smime.c speed.c spkac.c \
	srp.c ts.c verify.c version.c rehash.c x509.c ct.c

EXE_OBJ	= openssl.o $(OBJ) $(EXTRA_OBJ) $(RAND_OBJ)
EXE_SRC = openssl.c $(SRC) $(EXTRA_SRC) $(RAND_SRC)

HEADER=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h timeouts.h

ALL=    $(GENERAL) $(EXE_SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	exe

exe:	$(EXE)

openssl-vms.cnf: openssl.cnf
	$(PERL) $(TOP)/VMS/VMSify-conf.pl < openssl.cnf > openssl-vms.cnf

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@set -e; for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@set -e; for i in $(SCRIPTS); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	 done
	@cp openssl.cnf $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	chmod 644 $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	mv -f  $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

uninstall:
	@set -e; for i in $(EXE); \
	do  \
		echo $(RM) $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
		$(RM) $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
	done;
	@set -e; for i in $(SCRIPTS); \
	do  \
		echo $(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
		$(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
	done
	$(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

tags:
	ctags $(EXE_SRC) $(HEADER)

tests:

lint:
	echo nope >fluff

update: openssl-vms.cnf local_depend

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(EXE_SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) build_libssl)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) build_libcrypto)

$(EXE): progs.h $(EXE_OBJ) $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(EXE)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO)" ; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$(EXE) OBJECTS="$(EXE_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl Makefile
	$(RM) progs.h
	$(PERL) progs.pl $(COMMANDS) >progs.h
	$(RM) openssl.o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../crypto/include/internal/cryptlib.h
app_rand.o: ../crypto/include/internal/ct_int.h ../e_os.h
app_rand.o: ../include/openssl/asn1.h ../include/openssl/bio.h
app_rand.o: ../include/openssl/buffer.h ../include/openssl/conf.h
app_rand.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
app_rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
app_rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
app_rand.o: ../include/openssl/err.h ../include/openssl/evp.h
app_rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
app_rand.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
app_rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
app_rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
app_rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
app_rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
app_rand.o: ../include/openssl/x509v3.h app_rand.c apps.h progs.h
apps.o: ../crypto/include/internal/cryptlib.h
apps.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
apps.o: ../include/openssl/bio.h ../include/openssl/bn.h
apps.o: ../include/openssl/buffer.h ../include/openssl/comp.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
apps.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
apps.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
apps.o: ../include/openssl/err.h ../include/openssl/evp.h
apps.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
apps.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
apps.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
apps.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
apps.o: ../include/openssl/pem.h ../include/openssl/pem2.h
apps.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
apps.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
apps.o: ../include/openssl/sha.h ../include/openssl/srtp.h
apps.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
apps.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
apps.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
apps.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
apps.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
apps.o: ../include/openssl/x509v3.h apps.c apps.h progs.h
asn1pars.o: ../crypto/include/internal/cryptlib.h
asn1pars.o: ../crypto/include/internal/ct_int.h ../e_os.h
asn1pars.o: ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
asn1pars.o: ../include/openssl/err.h ../include/openssl/evp.h
asn1pars.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
asn1pars.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
asn1pars.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
asn1pars.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
asn1pars.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
asn1pars.o: ../include/openssl/safestack.h ../include/openssl/sha.h
asn1pars.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
asn1pars.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
asn1pars.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
asn1pars.o: asn1pars.c progs.h
ca.o: ../crypto/include/internal/cryptlib.h ../crypto/include/internal/ct_int.h
ca.o: ../crypto/include/internal/x509_int.h ../e_os.h ../include/openssl/asn1.h
ca.o: ../include/openssl/bio.h ../include/openssl/bn.h
ca.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ca.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ca.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ca.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ca.o: ../include/openssl/err.h ../include/openssl/evp.h
ca.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ca.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ca.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ca.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ca.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ca.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ca.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ca.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ca.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ca.c
ca.o: progs.h
ciphers.o: ../crypto/include/internal/cryptlib.h
ciphers.o: ../crypto/include/internal/ct_int.h ../e_os.h
ciphers.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ciphers.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ciphers.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ciphers.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ciphers.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ciphers.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ciphers.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ciphers.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ciphers.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ciphers.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ciphers.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ciphers.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ciphers.o: ciphers.c progs.h
cms.o: ../crypto/include/internal/cryptlib.h
cms.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
cms.o: ../include/openssl/bio.h ../include/openssl/buffer.h
cms.o: ../include/openssl/cms.h ../include/openssl/conf.h
cms.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
cms.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
cms.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
cms.o: ../include/openssl/err.h ../include/openssl/evp.h
cms.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
cms.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
cms.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cms.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
cms.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
cms.o: ../include/openssl/safestack.h ../include/openssl/sha.h
cms.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
cms.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
cms.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h cms.c
cms.o: progs.h
crl.o: ../crypto/include/internal/cryptlib.h
crl.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
crl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
crl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
crl.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
crl.o: ../include/openssl/engine.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl.o: ../include/openssl/x509v3.h apps.h crl.c progs.h
crl2p7.o: ../crypto/include/internal/cryptlib.h
crl2p7.o: ../crypto/include/internal/ct_int.h ../e_os.h
crl2p7.o: ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl2p7.o: ../include/openssl/err.h ../include/openssl/evp.h
crl2p7.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
crl2p7.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
crl2p7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl2p7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl2p7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl2p7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl2p7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl2p7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl2p7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
crl2p7.o: crl2p7.c progs.h
ct.o: ../crypto/include/internal/cryptlib.h ../crypto/include/internal/ct_int.h
ct.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ct.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ct.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ct.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ct.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ct.o: ../include/openssl/engine.h ../include/openssl/err.h
ct.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ct.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ct.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ct.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ct.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ct.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ct.o: ../include/openssl/sha.h ../include/openssl/stack.h
ct.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ct.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ct.o: ../include/openssl/x509v3.h apps.h ct.c progs.h
dgst.o: ../crypto/include/internal/cryptlib.h
dgst.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
dgst.o: ../include/openssl/bio.h ../include/openssl/buffer.h
dgst.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dgst.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dgst.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dgst.o: ../include/openssl/engine.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/hmac.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dgst.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dgst.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dgst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dgst.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dgst.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dgst.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dgst.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h dgst.c
dgst.o: progs.h
dhparam.o: ../crypto/include/internal/cryptlib.h
dhparam.o: ../crypto/include/internal/ct_int.h ../e_os.h
dhparam.o: ../include/openssl/asn1.h ../include/openssl/bio.h
dhparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dhparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dhparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dhparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dhparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dhparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dhparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dhparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dhparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dhparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dhparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dhparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dhparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dhparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dhparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dhparam.o: ../include/openssl/x509v3.h apps.h dhparam.c progs.h
dsa.o: ../crypto/include/internal/cryptlib.h
dsa.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
dsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
dsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dsa.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
dsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dsa.o: ../include/openssl/engine.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsa.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsa.o: ../include/openssl/x509v3.h apps.h dsa.c progs.h
dsaparam.o: ../crypto/include/internal/cryptlib.h
dsaparam.o: ../crypto/include/internal/ct_int.h ../e_os.h
dsaparam.o: ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsaparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsaparam.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dsaparam.o: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsaparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsaparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsaparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsaparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsaparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dsaparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
dsaparam.o: dsaparam.c progs.h
ec.o: ../crypto/include/internal/cryptlib.h ../crypto/include/internal/ct_int.h
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ec.o: ../include/openssl/err.h ../include/openssl/evp.h
ec.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ec.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ec.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ec.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ec.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ec.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ec.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ec.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ec.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ec.c
ec.o: progs.h
ecparam.o: ../crypto/include/internal/cryptlib.h
ecparam.o: ../crypto/include/internal/ct_int.h ../e_os.h
ecparam.o: ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/engine.h ../include/openssl/err.h
ecparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ecparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ecparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ecparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ecparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ecparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ecparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ecparam.o: ../include/openssl/x509v3.h apps.h ecparam.c progs.h
enc.o: ../crypto/include/internal/cryptlib.h
enc.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
enc.o: ../include/openssl/bio.h ../include/openssl/buffer.h
enc.o: ../include/openssl/comp.h ../include/openssl/conf.h
enc.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
enc.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
enc.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
enc.o: ../include/openssl/err.h ../include/openssl/evp.h
enc.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
enc.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enc.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.o: ../include/openssl/rand.h ../include/openssl/safestack.h
enc.o: ../include/openssl/sha.h ../include/openssl/stack.h
enc.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
enc.o: ../include/openssl/x509v3.h apps.h enc.c progs.h
engine.o: ../crypto/include/internal/cryptlib.h
engine.o: ../crypto/include/internal/ct_int.h ../e_os.h
engine.o: ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/buffer.h ../include/openssl/comp.h
engine.o: ../include/openssl/conf.h ../include/openssl/crypto.h
engine.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
engine.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
engine.o: ../include/openssl/err.h ../include/openssl/evp.h
engine.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
engine.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.o: ../include/openssl/pem.h ../include/openssl/pem2.h
engine.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
engine.o: ../include/openssl/sha.h ../include/openssl/srtp.h
engine.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
engine.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
engine.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
engine.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
engine.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
engine.o: engine.c progs.h
errstr.o: ../crypto/include/internal/cryptlib.h
errstr.o: ../crypto/include/internal/ct_int.h ../e_os.h
errstr.o: ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/buffer.h ../include/openssl/comp.h
errstr.o: ../include/openssl/conf.h ../include/openssl/crypto.h
errstr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
errstr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
errstr.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
errstr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
errstr.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
errstr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
errstr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
errstr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
errstr.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
errstr.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
errstr.o: errstr.c progs.h
gendsa.o: ../crypto/include/internal/cryptlib.h
gendsa.o: ../crypto/include/internal/ct_int.h ../e_os.h
gendsa.o: ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
gendsa.o: ../include/openssl/err.h ../include/openssl/evp.h
gendsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
gendsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
gendsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
gendsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
gendsa.o: gendsa.c progs.h
genpkey.o: ../crypto/include/internal/cryptlib.h
genpkey.o: ../crypto/include/internal/ct_int.h ../e_os.h
genpkey.o: ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genpkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
genpkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
genpkey.o: ../include/openssl/err.h ../include/openssl/evp.h
genpkey.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
genpkey.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
genpkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
genpkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
genpkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genpkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
genpkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
genpkey.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
genpkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
genpkey.o: genpkey.c progs.h
genrsa.o: ../crypto/include/internal/cryptlib.h
genrsa.o: ../crypto/include/internal/ct_int.h ../e_os.h
genrsa.o: ../include/openssl/asn1.h ../include/openssl/bio.h
genrsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
genrsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
genrsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
genrsa.o: ../include/openssl/engine.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genrsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genrsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genrsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genrsa.o: ../include/openssl/x509v3.h apps.h genrsa.c progs.h
nseq.o: ../crypto/include/internal/cryptlib.h
nseq.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
nseq.o: ../include/openssl/bio.h ../include/openssl/buffer.h
nseq.o: ../include/openssl/conf.h ../include/openssl/crypto.h
nseq.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
nseq.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
nseq.o: ../include/openssl/engine.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/lhash.h
nseq.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
nseq.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
nseq.o: ../include/openssl/pem.h ../include/openssl/pem2.h
nseq.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
nseq.o: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
nseq.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
nseq.o: ../include/openssl/x509v3.h apps.h nseq.c progs.h
ocsp.o: ../crypto/include/internal/cryptlib.h
ocsp.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
ocsp.o: ../include/openssl/bio.h ../include/openssl/bn.h
ocsp.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ocsp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ocsp.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ocsp.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ocsp.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ocsp.o: ../include/openssl/err.h ../include/openssl/evp.h
ocsp.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ocsp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ocsp.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ocsp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ocsp.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ocsp.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ocsp.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ocsp.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ocsp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ocsp.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ocsp.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ocsp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ocsp.c
ocsp.o: progs.h
openssl.o: ../crypto/include/internal/cryptlib.h
openssl.o: ../crypto/include/internal/ct_int.h ../e_os.h
openssl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
openssl.o: ../include/openssl/buffer.h ../include/openssl/comp.h
openssl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
openssl.o: ../include/openssl/err.h ../include/openssl/evp.h
openssl.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
openssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
openssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
openssl.o: ../include/openssl/x509v3.h apps.h openssl.c progs.h s_apps.h
opt.o: ../crypto/include/internal/cryptlib.h
opt.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
opt.o: ../include/openssl/bio.h ../include/openssl/buffer.h
opt.o: ../include/openssl/conf.h ../include/openssl/crypto.h
opt.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
opt.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
opt.o: ../include/openssl/engine.h ../include/openssl/err.h
opt.o: ../include/openssl/evp.h ../include/openssl/lhash.h
opt.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
opt.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
opt.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
opt.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
opt.o: ../include/openssl/sha.h ../include/openssl/stack.h
opt.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
opt.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
opt.o: ../include/openssl/x509v3.h apps.h opt.c progs.h
passwd.o: ../crypto/include/internal/cryptlib.h
passwd.o: ../crypto/include/internal/ct_int.h ../e_os.h
passwd.o: ../include/openssl/asn1.h ../include/openssl/bio.h
passwd.o: ../include/openssl/buffer.h ../include/openssl/conf.h
passwd.o: ../include/openssl/crypto.h ../include/openssl/des.h
passwd.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
passwd.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
passwd.o: ../include/openssl/engine.h ../include/openssl/err.h
passwd.o: ../include/openssl/evp.h ../include/openssl/lhash.h
passwd.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
passwd.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
passwd.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
passwd.o: ../include/openssl/rand.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
passwd.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
passwd.o: ../include/openssl/x509v3.h apps.h passwd.c progs.h
pkcs12.o: ../crypto/include/internal/cryptlib.h
pkcs12.o: ../crypto/include/internal/ct_int.h ../e_os.h
pkcs12.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs12.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs12.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs12.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs12.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs12.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs12.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs12.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs12.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs12.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs12.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs12.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs12.o: ../include/openssl/x509v3.h apps.h pkcs12.c progs.h
pkcs7.o: ../crypto/include/internal/cryptlib.h
pkcs7.o: ../crypto/include/internal/ct_int.h ../e_os.h
pkcs7.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs7.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs7.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs7.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkcs7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs7.o: pkcs7.c progs.h
pkcs8.o: ../crypto/include/internal/cryptlib.h
pkcs8.o: ../crypto/include/internal/ct_int.h ../e_os.h
pkcs8.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs8.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs8.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs8.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs8.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs8.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs8.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs8.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs8.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs8.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs8.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs8.o: ../include/openssl/x509v3.h apps.h pkcs8.c progs.h
pkey.o: ../crypto/include/internal/cryptlib.h
pkey.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
pkey.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkey.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkey.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
pkey.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
pkey.o: ../include/openssl/engine.h ../include/openssl/err.h
pkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkey.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkey.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkey.o: ../include/openssl/x509v3.h apps.h pkey.c progs.h
pkeyparam.o: ../crypto/include/internal/cryptlib.h
pkeyparam.o: ../crypto/include/internal/ct_int.h ../e_os.h
pkeyparam.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyparam.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkeyparam.o: ../include/openssl/err.h ../include/openssl/evp.h
pkeyparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkeyparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkeyparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkeyparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyparam.o: pkeyparam.c progs.h
pkeyutl.o: ../crypto/include/internal/cryptlib.h
pkeyutl.o: ../crypto/include/internal/ct_int.h ../e_os.h
pkeyutl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyutl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyutl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkeyutl.o: ../include/openssl/err.h ../include/openssl/evp.h
pkeyutl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkeyutl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkeyutl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyutl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyutl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyutl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyutl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyutl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkeyutl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyutl.o: pkeyutl.c progs.h
prime.o: ../crypto/include/internal/cryptlib.h
prime.o: ../crypto/include/internal/ct_int.h ../e_os.h
prime.o: ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/engine.h ../include/openssl/err.h
prime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
prime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
prime.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
prime.o: ../include/openssl/sha.h ../include/openssl/stack.h
prime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
prime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
prime.o: ../include/openssl/x509v3.h apps.h prime.c progs.h
rand.o: ../crypto/include/internal/cryptlib.h
rand.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
rand.o: ../include/openssl/bio.h ../include/openssl/buffer.h
rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rand.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rand.o: ../include/openssl/engine.h ../include/openssl/err.h
rand.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rand.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rand.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rand.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rand.o: progs.h rand.c
rehash.o: ../crypto/include/internal/cryptlib.h
rehash.o: ../crypto/include/internal/ct_int.h ../e_os.h
rehash.o: ../include/internal/o_dir.h ../include/openssl/asn1.h
rehash.o: ../include/openssl/bio.h ../include/openssl/buffer.h
rehash.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rehash.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rehash.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rehash.o: ../include/openssl/engine.h ../include/openssl/err.h
rehash.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rehash.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rehash.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rehash.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rehash.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rehash.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
rehash.o: ../include/openssl/sha.h ../include/openssl/stack.h
rehash.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rehash.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rehash.o: ../include/openssl/x509v3.h apps.h progs.h rehash.c
req.o: ../crypto/include/internal/cryptlib.h
req.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
req.o: ../include/openssl/bio.h ../include/openssl/bn.h
req.o: ../include/openssl/buffer.h ../include/openssl/conf.h
req.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
req.o: ../include/openssl/engine.h ../include/openssl/err.h
req.o: ../include/openssl/evp.h ../include/openssl/lhash.h
req.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
req.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
req.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
req.o: ../include/openssl/pem.h ../include/openssl/pem2.h
req.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
req.o: ../include/openssl/safestack.h ../include/openssl/sha.h
req.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
req.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
req.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
req.o: req.c
rsa.o: ../crypto/include/internal/cryptlib.h
rsa.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
rsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
rsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsa.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rsa.o: ../include/openssl/err.h ../include/openssl/evp.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsa.o: ../include/openssl/x509v3.h apps.h progs.h rsa.c
rsautl.o: ../crypto/include/internal/cryptlib.h
rsautl.o: ../crypto/include/internal/ct_int.h ../e_os.h
rsautl.o: ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rsautl.o: ../include/openssl/err.h ../include/openssl/evp.h
rsautl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsautl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsautl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsautl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsautl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsautl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsautl.o: ../include/openssl/x509v3.h apps.h progs.h rsautl.c
s_cb.o: ../crypto/include/internal/cryptlib.h
s_cb.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
s_cb.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_cb.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_cb.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.o: ../include/openssl/dh.h ../include/openssl/dtls1.h
s_cb.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_cb.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_cb.o: ../include/openssl/engine.h ../include/openssl/err.h
s_cb.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_cb.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_cb.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_cb.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_cb.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_cb.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_cb.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_cb.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_cb.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_cb.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_cb.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_cb.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_cb.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_cb.o: progs.h s_apps.h s_cb.c
s_client.o: ../crypto/include/internal/cryptlib.h
s_client.o: ../crypto/include/internal/ct_int.h ../e_os.h
s_client.o: ../include/openssl/asn1.h ../include/openssl/async.h
s_client.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_client.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_client.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_client.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_client.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_client.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_client.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_client.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_client.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_client.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_client.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_client.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_client.o: ../include/openssl/srp.h ../include/openssl/srtp.h
s_client.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_client.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_client.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_client.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_client.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_client.o: progs.h s_apps.h s_client.c timeouts.h
s_server.o: ../crypto/include/internal/cryptlib.h
s_server.o: ../crypto/include/internal/ct_int.h ../e_os.h
s_server.o: ../include/openssl/asn1.h ../include/openssl/async.h
s_server.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_server.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_server.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_server.o: ../include/openssl/dh.h ../include/openssl/dtls1.h
s_server.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_server.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_server.o: ../include/openssl/engine.h ../include/openssl/err.h
s_server.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_server.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_server.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_server.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_server.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_server.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_server.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_server.o: ../include/openssl/srp.h ../include/openssl/srtp.h
s_server.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_server.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_server.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_server.o: progs.h s_apps.h s_server.c timeouts.h
s_socket.o: ../crypto/include/internal/cryptlib.h
s_socket.o: ../crypto/include/internal/ct_int.h ../e_os.h
s_socket.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_socket.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_socket.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_socket.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_socket.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_socket.o: ../include/openssl/err.h ../include/openssl/evp.h
s_socket.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_socket.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_socket.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
s_socket.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_socket.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_socket.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_socket.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_socket.o: progs.h s_apps.h s_socket.c
s_time.o: ../crypto/include/internal/cryptlib.h
s_time.o: ../crypto/include/internal/ct_int.h ../e_os.h
s_time.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_time.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_time.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_time.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_time.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_time.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_time.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_time.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
s_time.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_time.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_time.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_time.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_time.o: progs.h s_apps.h s_time.c
sess_id.o: ../crypto/include/internal/cryptlib.h
sess_id.o: ../crypto/include/internal/ct_int.h ../e_os.h
sess_id.o: ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/buffer.h ../include/openssl/comp.h
sess_id.o: ../include/openssl/conf.h ../include/openssl/crypto.h
sess_id.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
sess_id.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
sess_id.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
sess_id.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sess_id.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
sess_id.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
sess_id.o: ../include/openssl/sha.h ../include/openssl/srtp.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sess_id.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sess_id.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
sess_id.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
sess_id.o: progs.h sess_id.c
smime.o: ../crypto/include/internal/cryptlib.h
smime.o: ../crypto/include/internal/ct_int.h ../e_os.h
smime.o: ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
smime.o: ../include/openssl/err.h ../include/openssl/evp.h
smime.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
smime.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
smime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
smime.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
smime.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
smime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
smime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
smime.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
smime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
smime.o: progs.h smime.c
speed.o: ../crypto/include/internal/cryptlib.h
speed.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/aes.h
speed.o: ../include/openssl/asn1.h ../include/openssl/bio.h
speed.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
speed.o: ../include/openssl/buffer.h ../include/openssl/camellia.h
speed.o: ../include/openssl/cast.h ../include/openssl/conf.h
speed.o: ../include/openssl/crypto.h ../include/openssl/des.h
speed.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
speed.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
speed.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
speed.o: ../include/openssl/err.h ../include/openssl/evp.h
speed.o: ../include/openssl/hmac.h ../include/openssl/idea.h
speed.o: ../include/openssl/lhash.h ../include/openssl/md4.h
speed.o: ../include/openssl/md5.h ../include/openssl/mdc2.h
speed.o: ../include/openssl/modes.h ../include/openssl/obj_mac.h
speed.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
speed.o: ../include/openssl/rand.h ../include/openssl/rc2.h
speed.o: ../include/openssl/rc4.h ../include/openssl/ripemd.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/seed.h ../include/openssl/sha.h
speed.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
speed.o: ../include/openssl/txt_db.h ../include/openssl/whrlpool.h
speed.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
speed.o: ../include/openssl/x509v3.h apps.h progs.h speed.c testdsa.h testrsa.h
spkac.o: ../crypto/include/internal/cryptlib.h
spkac.o: ../crypto/include/internal/ct_int.h ../e_os.h
spkac.o: ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
spkac.o: ../include/openssl/err.h ../include/openssl/evp.h
spkac.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
spkac.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
spkac.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
spkac.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
spkac.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
spkac.o: ../include/openssl/safestack.h ../include/openssl/sha.h
spkac.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
spkac.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
spkac.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
spkac.o: progs.h spkac.c
srp.o: ../crypto/include/internal/cryptlib.h
srp.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
srp.o: ../include/openssl/bio.h ../include/openssl/bn.h
srp.o: ../include/openssl/buffer.h ../include/openssl/conf.h
srp.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
srp.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
srp.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
srp.o: ../include/openssl/err.h ../include/openssl/evp.h
srp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
srp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
srp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
srp.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
srp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
srp.o: ../include/openssl/srp.h ../include/openssl/stack.h
srp.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
srp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
srp.o: ../include/openssl/x509v3.h apps.h progs.h srp.c
ts.o: ../crypto/include/internal/cryptlib.h ../crypto/include/internal/ct_int.h
ts.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ts.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ts.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ts.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ts.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ts.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ts.o: ../include/openssl/engine.h ../include/openssl/err.h
ts.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ts.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ts.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ts.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ts.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ts.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ts.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ts.o: ../include/openssl/sha.h ../include/openssl/stack.h
ts.o: ../include/openssl/symhacks.h ../include/openssl/ts.h
ts.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ts.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
ts.o: ts.c
verify.o: ../crypto/include/internal/cryptlib.h
verify.o: ../crypto/include/internal/ct_int.h ../e_os.h
verify.o: ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
verify.o: ../include/openssl/err.h ../include/openssl/evp.h
verify.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
verify.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
verify.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
verify.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
verify.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify.o: ../include/openssl/safestack.h ../include/openssl/sha.h
verify.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
verify.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
verify.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
verify.o: progs.h verify.c
version.o: ../crypto/include/internal/cryptlib.h
version.o: ../crypto/include/internal/ct_int.h ../e_os.h
version.o: ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
version.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
version.o: ../include/openssl/engine.h ../include/openssl/err.h
version.o: ../include/openssl/evp.h ../include/openssl/idea.h
version.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
version.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
version.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
version.o: ../include/openssl/rc4.h ../include/openssl/safestack.h
version.o: ../include/openssl/sha.h ../include/openssl/stack.h
version.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
version.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
version.o: ../include/openssl/x509v3.h apps.h progs.h version.c
x509.o: ../crypto/include/internal/cryptlib.h
x509.o: ../crypto/include/internal/ct_int.h ../e_os.h ../include/openssl/asn1.h
x509.o: ../include/openssl/bio.h ../include/openssl/bn.h
x509.o: ../include/openssl/buffer.h ../include/openssl/conf.h
x509.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
x509.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
x509.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
x509.o: ../include/openssl/engine.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/lhash.h
x509.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
x509.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
x509.o: ../include/openssl/pem.h ../include/openssl/pem2.h
x509.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
x509.o: ../include/openssl/safestack.h ../include/openssl/sha.h
x509.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
x509.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
x509.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
x509.o: progs.h x509.c
