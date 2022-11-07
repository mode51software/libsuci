
#include <openssl/evp.h>
#include "suci_calcs.h"

#ifndef SUCIC_UTILS_H
#define SUCIC_UTILS_H

#ifdef SUCIC_TEST_ENABLED
#define DLOG printf
#define ELOG printf
#define ILOG printf
#define HLOG suci_printHex
#else
#define DLOG //
#define ELOG //
#define ILOG //
#define HLOG //
#endif // SUCIC_TEST_ENABLED


int suci_loadKeyBytes(short is_privkey, uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** eck);
int suci_loadPubKeyBytes(uint8_t* pub_bytes, int priv_bytes_len, EVP_PKEY** pubkey);
int suci_loadPrivKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey);
EVP_PKEY* suci_loadPrivateKeyFile(uint8_t* filename, EVP_PKEY** pkey);
EVP_PKEY* suci_loadPublicKeyFile(uint8_t* filename, EVP_PKEY** pkey);
int suci_parsePublicKey(unsigned char* curve_name, EVP_PKEY** pkey);
EVP_PKEY* suci_setECParams(EVP_PKEY *eck, int nid);
void suci_printHex(const char *label, const uint8_t *v, size_t len);
void suci_sprintfHex(uint8_t* in, uint8_t* out, size_t inlen, short should_swapbytes);
int suci_getCurveName(EVP_PKEY* privkey, unsigned char* outbuf);
void suci_getEvpPrivKey(EVP_PKEY* privkey, BIGNUM* out_bignum);
void suci_unpackRawSuciBytes(uint8_t* raw_sucibytesin, size_t raw_sucibytesin_sz, SuciData * raw_sucibytesout, size_t ue_keysz);
void suci_cleanupSuciData(SuciData* suciData);
void suci_unpackSuciString(uint8_t* sucistr_in, SuciData * raw_sucibytesout, size_t ue_keysz);

#endif //SUCIC_UTILS_H
