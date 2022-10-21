
#include <openssl/evp.h>

#ifndef SUCIC_SUCIC_UTILS_H
#define SUCIC_UTILS_H

#ifdef SUCIC_TEST_ENABLED
#define DLOG printf
#define ELOG printf
#define ILOG printf
#define HLOG sucic_printHex
#else
#define DLOG //
#define ELOG //
#define ILOG //
#define HLOG //
#endif // SUCIC_TEST_ENABLED


int sucic_loadKeyBytes(short is_privkey, uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** eck);
int sucic_loadPubKeyBytes(uint8_t* pub_bytes, int priv_bytes_len, EVP_PKEY** pubkey);
int sucic_loadPrivKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey);
EVP_PKEY* sucic_loadPrivateKeyFile(const char* filename, EVP_PKEY** pkey);
EVP_PKEY* sucic_loadPublicKeyFile(const char* filename, EVP_PKEY** pkey);
int suci_parsePublicKey(unsigned char* curve_name, unsigned char* pkey);
EVP_PKEY* sucic_setECParams(EVP_PKEY *eck, int nid);
void sucic_printHex(const char *label, const uint8_t *v, size_t len);
int sucic_getCurveName(EVP_PKEY* privkey, unsigned char* outbuf);
void sucic_getEvpPrivKey(EVP_PKEY* privkey, BIGNUM* out_bignum);

#endif //SUCIC_UTILS_H
