/* $Id: */


#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>

#ifdef __cplusplus
}
#endif

MODULE = Crypt::OpenSSL::DSA         PACKAGE = Crypt::OpenSSL::DSA

PROTOTYPES: DISABLE

BOOT:
    ERR_load_crypto_strings();

DSA *
new(CLASS)
        char * CLASS
    CODE:
        RETVAL = DSA_new();
    OUTPUT:
        RETVAL

void
DESTROY(dsa)
        DSA *dsa
    CODE:
        DSA_free(dsa);

DSA *
generate_parameters(CLASS, bits, seed = "")
        char * CLASS
        int bits
        char *seed
    PREINIT:
        DSA * dsa;
        int seed_len = 0;
    CODE:
        if(seed)
          seed_len = strlen(seed);
        dsa = DSA_generate_parameters(bits, seed, seed_len, NULL, NULL, NULL, NULL);
        if (!dsa)
          croak(ERR_reason_error_string(ERR_get_error()));
        RETVAL = dsa;
    OUTPUT:
        RETVAL

int
generate_key(dsa)
        DSA * dsa
    CODE:
        RETVAL = DSA_generate_key(dsa);
    OUTPUT:
        RETVAL

DSA_SIG *
do_sign(dsa, value)
        DSA * dsa
        char *value
    PREINIT:
        DSA_SIG * sig;
        char * CLASS = "Crypt::OpenSSL::DSA::Signature";
    CODE:
        if (!(sig = DSA_do_sign((const unsigned char *)value, strlen(value), dsa))) {
          croak("Error in dsa_sign: %s",ERR_error_string(ERR_get_error(), NULL));
        }
        RETVAL = sig;
    OUTPUT:
        RETVAL

SV *
sign(dsa, dgst)
        DSA * dsa
        char *dgst
    PREINIT:
        unsigned char *sigret;
        unsigned int siglen;
    CODE:
        siglen = DSA_size(dsa);
        sigret = malloc(siglen);
        if (!(DSA_sign(0, (const unsigned char *)dgst, strlen(dgst), sigret, &siglen, dsa))) {
          croak("Error in dsa_sign: %s",ERR_error_string(ERR_get_error(), NULL));
        }
        RETVAL = newSVpvn(sigret, siglen);
        free(sigret);
    OUTPUT:
        RETVAL

int
verify(dsa, dgst, sigbuf)
        DSA * dsa
        char *dgst
        char *sigbuf
    CODE:
        RETVAL = DSA_verify(0, dgst, strlen(dgst), sigbuf, strlen(sigbuf), dsa);
    OUTPUT:
        RETVAL

int
do_verify(dsa, dgst, sig)
        DSA *dsa
        char *dgst
        DSA_SIG *sig
    CODE:
        RETVAL = DSA_do_verify(dgst, strlen(dgst), sig, dsa);
    OUTPUT:
        RETVAL

DSA *
read_params(CLASS, filename)
        char *CLASS
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "r")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_read_DSAparams(f, NULL, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

int
write_params(dsa, filename)
        DSA * dsa
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "w")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_write_DSAparams(f, dsa);
        fclose(f);
    OUTPUT:
        RETVAL

DSA *
read_pub_key(CLASS, filename)
        char *CLASS
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "r")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_read_DSA_PUBKEY(f, NULL, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

int
write_pub_key(dsa, filename)
        DSA * dsa
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "w")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_write_DSA_PUBKEY(f, dsa);
        fclose(f);
    OUTPUT:
        RETVAL

DSA *
read_priv_key(CLASS, filename)
        char *CLASS
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "r")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_read_DSAPrivateKey(f, NULL, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

int
write_priv_key(dsa, filename)
        DSA * dsa
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "w")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_write_DSAPrivateKey(f, dsa, NULL, NULL, 0, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

SV *
get_p(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->p, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_q(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 20);
        len = BN_bn2bin(dsa->q, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_g(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->g, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_pub_key(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->pub_key, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

MODULE = Crypt::OpenSSL::DSA    PACKAGE = Crypt::OpenSSL::DSA::Signature

void
DESTORY(dsa_sig)
        DSA_SIG *dsa_sig
    CODE:
        DSA_SIG_free(dsa_sig);

SV *
get_r(dsa_sig)
        DSA_SIG *dsa_sig
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa_sig->r, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_s(dsa_sig)
        DSA_SIG *dsa_sig
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa_sig->s, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL
