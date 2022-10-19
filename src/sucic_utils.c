
#include "sucic_utils.h"

#include <openssl/evp.h>
#include <pem.h>
#include <core_names.h>

EVP_PKEY* sucic_loadPrivateKeyFile(const char* filename, EVP_PKEY** pkey) {

    FILE* fp = fopen(filename, "rb");

    if(fp == NULL) {
        return NULL;
    } else {
        EVP_PKEY* retkey = d2i_PrivateKey_fp(fp, pkey); //, NULL, NULL);
        return retkey;
    }
}

EVP_PKEY* sucic_loadPublicKeyFile(const char* filename, EVP_PKEY** pkey) {

    FILE* fp = fopen(filename, "rb");

    if(fp == NULL) {
        return NULL;
    } else {
        EVP_PKEY* retkey = d2i_PUBKEY_fp(fp, pkey); //, NULL, NULL);
        return retkey;
    }
}

// https://github.com/openssl/openssl/issues/16989
int sucic_loadPrivKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey) {
    return sucic_loadKeyBytes(1, priv_bytes, priv_bytes_len, privkey);
}

int sucic_loadPubKeyBytes(uint8_t* pub_bytes, int priv_bytes_len, EVP_PKEY** pubkey) {
    return sucic_loadKeyBytes(0, pub_bytes, priv_bytes_len, pubkey);
}

int sucic_loadKeyBytes(short is_privkey, uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey) {

    unsigned char* key_buf = OPENSSL_malloc(priv_bytes_len); // surely enough

    for(int i=0; i<priv_bytes_len; i++) {
        key_buf[i] = priv_bytes[i];
    }
    const unsigned char* key_buf_ptr = key_buf;
    //*privkey = EVP_EC_gen("P-256");
    HLOG("priv #2   ", priv_bytes, priv_bytes_len);
    *privkey = sucic_setECParams(*privkey, NID_X9_62_prime256v1);
    EVP_PKEY* privkeyloc = is_privkey ?
                           d2i_PrivateKey(EVP_PKEY_EC, privkey, &key_buf, priv_bytes_len)
                                      : d2i_PublicKey(EVP_PKEY_EC, privkey, &key_buf_ptr, priv_bytes_len);
    *privkey = privkeyloc;

    //printf("Generated new key len=%d sz=%d\n", pubklen, EVP_PKEY_get_size(*privkey));

/*    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 "prime256v1", 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    //EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X9_62_prime256v1, NULL);

    EVP_PKEY_fromdata_init(pctx);
    int res = EVP_PKEY_fromdata(pctx, privkey,
                             OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                             params);

    EVP_PKEY* keyloc = is_privkey ?
                           d2i_PrivateKey(EVP_PKEY_EC, privkey, &key_buf, priv_bytes_len) //&priv_bytes)
                                      : d2i_PublicKey(EVP_PKEY_EC, privkey, &key_buf_ptr, priv_bytes_len); //&priv_bytes);
*/
    HLOG("priv #3   ", priv_bytes, priv_bytes_len);

    OPENSSL_free(key_buf);

    if(*privkey == NULL) {
        return 1;
    }
    return 0;

/*    EVP_PKEY* neck = EVP_PKEY_new();
    neck = sucic_setECParams(neck, NID_X9_62_prime256v1);
    neck = is_privkey ?
            d2i_PrivateKey(EVP_PKEY_EC, &neck, &pk_enc, pubklen)
            : d2i_PublicKey(EVP_PKEY_EC, &neck, &pk_enc, pubklen);

    HLOG("priv #5   ", pk_enc, priv_bytes_len);

    if(neck == NULL) {
        return 1;
    } else {
        printf("Loaded %d bytes\n", EVP_PKEY_get_size(neck));
        printf("neck = %p\n", neck);
        printf("eq: %d\n", EVP_PKEY_eq(*privkey, neck));
        return 0;
    }*/
}

int suci_parsePublicKey(unsigned char* curve_name, unsigned char* pkey) {
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    //EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X9_62_prime256v1, NULL);

    EVP_PKEY_fromdata_init(pctx);
    return EVP_PKEY_fromdata(pctx, &pkey,
                             OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                             params);
}

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

int sucic_getCurveName(EVP_PKEY* privkey, unsigned char* outbuf) {

    int len = 0;

    if (!EVP_PKEY_get_utf8_string_param(privkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        outbuf, sizeof(outbuf), &len)) {
        ELOG("Error getting priv param\n");
    } else {
        ILOG("Got priv param curve name=%s\n", outbuf);
    }
    return len;
}

void sucic_getEvpPrivKey(EVP_PKEY* privkey, BIGNUM* out_bignum) {
    if (!EVP_PKEY_get_bn_param(privkey, OSSL_PKEY_PARAM_PRIV_KEY, out_bignum)) {
        ELOG("Error getting privkey\n");
    } else {
        ILOG("Got priv key\n");
    }
}
