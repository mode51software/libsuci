
#include <openssl/evp.h>

#ifndef SUCIC_EC_XG_H
#define SUCIC_EC_XG_H

#define DLOG printf
#define ELOG printf
#define ILOG printf
#define HLOG sucic_printHex

EVP_PKEY* sucic_setECParams(EVP_PKEY *eck, int nid);
void sucic_printHex(const char *label, const uint8_t *v, size_t len);

#endif //SUCIC_EC_XG_H
