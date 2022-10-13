
#include <openssl/evp.h>

EVP_PKEY* sucic_setECParams(EVP_PKEY *eck, int nid) {
    const char p256params[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const char p384params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
    const char p521params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

    const unsigned char* params;
    switch(nid) {
        case NID_X9_62_prime256v1:
            params = p256params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p256params));
        case NID_secp384r1:
            params = p384params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p384params));
        case NID_secp521r1:
            params = p521params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p521params));
        default:
            return NULL;
    }
}

void sucic_printHex(const char *label, const uint8_t *v, size_t len) {
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", v[i]);
    }
    printf("\n");
}
