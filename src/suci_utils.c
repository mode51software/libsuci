
#include "suci_utils.h"
#include "suci_calcs.h"

#include <openssl/evp.h>
#include <pem.h>
#include <core_names.h>

EVP_PKEY* suci_loadKeyFile(const char* filename, EVP_PKEY** pkey, short is_public);

EVP_PKEY* suci_loadPrivateKeyFile(const char* filename, EVP_PKEY** pkey) {

/*    FILE* fp = fopen(filename, "rb");

    if(fp == NULL) {
        return NULL;
    } else {
        EVP_PKEY* retkey = d2i_PrivateKey_fp(fp, pkey); //, NULL, NULL);
        return retkey;
    }*/
    return suci_loadKeyFile(filename, pkey, 0);

}

EVP_PKEY* suci_loadPublicKeyFile(const char* filename, EVP_PKEY** pkey) {

/*    FILE* fp = fopen(filename, "rb");

    if(fp == NULL) {
        return NULL;
    } else {
        EVP_PKEY* retkey = d2i_PUBKEY_fp(fp, pkey); //, NULL, NULL);
        return retkey;
    }*/
    return suci_loadKeyFile(filename, pkey, 1);
}

EVP_PKEY* suci_loadKeyFile(const char* filename, EVP_PKEY** pkey, short is_public) {

    FILE* fp = fopen(filename, "rb");

    if(fp == NULL) {
        return NULL;
    } else {
        EVP_PKEY* retkey;
        retkey = is_public ? d2i_PUBKEY_fp(fp, pkey)
                : d2i_PrivateKey_fp(fp, pkey);
        return retkey;
    }
}

// https://github.com/openssl/openssl/issues/16989
int suci_loadPrivKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey) {
    return suci_loadKeyBytes(1, priv_bytes, priv_bytes_len, privkey);
}

int suci_loadPubKeyBytes(uint8_t* pub_bytes, int priv_bytes_len, EVP_PKEY** pubkey) {
    return suci_loadKeyBytes(0, pub_bytes, priv_bytes_len, pubkey);
}

int suci_loadKeyBytes(short is_privkey, uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey) {

    unsigned char* key_buf = OPENSSL_malloc(priv_bytes_len); // surely enough

    for(int i=0; i<priv_bytes_len; i++) {
        key_buf[i] = priv_bytes[i];
    }
    const unsigned char* key_buf_ptr = key_buf;
    //*privkey = EVP_EC_gen("P-256");
    *privkey = suci_setECParams(*privkey, NID_X9_62_prime256v1);
    EVP_PKEY* privkeyloc = is_privkey ?
                           d2i_PrivateKey(EVP_PKEY_EC, privkey, &key_buf, priv_bytes_len)
                                      : d2i_PublicKey(EVP_PKEY_EC, privkey, &key_buf_ptr, priv_bytes_len);
    *privkey = privkeyloc;

    HLOG("priv #3   ", priv_bytes, priv_bytes_len);

    OPENSSL_free(key_buf);

    if(*privkey == NULL) {
        return SUCIC_PUBKEYNOTLOADED;
    }
    return 0;
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

EVP_PKEY* suci_setECParams(EVP_PKEY *eck, int nid) {
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

void suci_printHex(const char *label, const uint8_t *v, size_t len) {
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", v[i]);
    }
    printf("\n");
}

void suci_sprintfHex(uint8_t* in, uint8_t* out, size_t inlen, short should_swapbytes) {
    uint8_t tmp[2];
    for (int i = 0; i < inlen; ++i) {
        if(should_swapbytes) {
            sprintf(tmp, "%02x", in[i]);
            memcpy(out + (i*2), &tmp[1], 1);
            memcpy(out + (i*2) + 1, &tmp[0], 1);
        } else {
            sprintf(out + (i*2), "%02x", in[i]);
        }
    }
    out[(inlen)*2] = '\0';
}

int suci_getCurveName(EVP_PKEY* privkey, unsigned char* outbuf) {

    int len = 0;

    if (!EVP_PKEY_get_utf8_string_param(privkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        outbuf, sizeof(outbuf), &len)) {
        ELOG("Error getting priv param\n");
    } else {
        ILOG("Got priv param curve name=%s\n", outbuf);
    }
    return len;
}

void suci_getEvpPrivKey(EVP_PKEY* privkey, BIGNUM* out_bignum) {
    if (!EVP_PKEY_get_bn_param(privkey, OSSL_PKEY_PARAM_PRIV_KEY, out_bignum)) {
        ELOG("Error getting privkey\n");
    } else {
        ILOG("Got priv key\n");
    }
}

void suci_unpackSuciString(uint8_t* sucistr_in, SuciData * raw_sucibytesout, size_t ue_keysz) {
    int sucistr_len = strlen(sucistr_in);
    if(sucistr_len < 1000) {
        int raw_sucibytesin_sz = (sucistr_len / 2) + 1;
        uint8_t* raw_sucibytesin = (uint8_t*) malloc(raw_sucibytesin_sz * sizeof(char));
        uint8_t tmp[3];
        tmp[2] = '\0';
        for(int i=0; i<sucistr_len; i+=2) {
            tmp[0] = sucistr_in[i];
            tmp[1] = sucistr_in[i + 1];
            raw_sucibytesin[i / 2] = strtol(tmp, NULL, 16);
        }
        suci_unpackRawSuciBytes(raw_sucibytesin, raw_sucibytesin_sz, raw_sucibytesout, ue_keysz);
        free(raw_sucibytesin);
    }
}

void suci_unpackRawSuciBytes(uint8_t* raw_sucibytesin, size_t raw_sucibytesin_sz, SuciData * raw_sucibytesout, size_t ue_keysz) {

    raw_sucibytesout->mac_key_sz = 8;
    raw_sucibytesout->enc_msin_sz = raw_sucibytesin_sz - ((raw_sucibytesout->mac_key_sz + ue_keysz) + 1);
    raw_sucibytesout->ue_key_sz = ue_keysz;

    raw_sucibytesout->ue_key = malloc(ue_keysz * sizeof(uint8_t));
    raw_sucibytesout->mac_key = malloc(raw_sucibytesout->mac_key_sz * sizeof(uint8_t));
    raw_sucibytesout->enc_msin = malloc(raw_sucibytesout->enc_msin_sz * sizeof(uint8_t));

    memcpy(raw_sucibytesout->ue_key, raw_sucibytesin, ue_keysz);
    memcpy(raw_sucibytesout->enc_msin, raw_sucibytesin + ue_keysz, sizeof(raw_sucibytesout->enc_msin));
    memcpy(raw_sucibytesout->mac_key, raw_sucibytesin + ue_keysz +  raw_sucibytesout->enc_msin_sz,
           raw_sucibytesout->mac_key_sz * sizeof(uint8_t));
}

void suci_cleanupSuciData(SuciData* suciData) {
    if(suciData->ue_key) { free(suciData->ue_key); }
    if(suciData->enc_msin) { free(suciData->enc_msin); }
    if(suciData->mac_key) { free(suciData->mac_key); }
    free(suciData);
}
