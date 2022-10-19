
#include <openssl/evp.h>

#ifndef SUCIC_SUCIC_CALCS_H
#define SUCIC_EC_XG_H

#define DLOG printf
#define ELOG printf
#define ILOG printf
#define HLOG sucic_printHex

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

#endif //SUCIC_SUCIC_CALCS_H
