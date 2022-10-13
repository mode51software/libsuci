
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <core_names.h>
#include <kdf.h>
#include <pem.h>

#include "sucic_utils.h"

// https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

int sucic_loadPrivKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** eck);
int sucic_loadPubKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** eck);
int sucic_loadKeyBytes(short is_privkey, uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** eck);
int sucic_genSharedKey(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** secret, size_t* secret_len);
EVP_PKEY* sucic_loadPrivateKeyFile(const char* filename, EVP_PKEY** pkey);
EVP_PKEY* sucic_loadPublicKeyFile(const char* filename, EVP_PKEY** pkey);
int suci_parsePublicKey(unsigned char* curve_name, unsigned char* pkey);
int sucic_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                  unsigned char *iv, unsigned char *plaintext, int* plaintext_len);

int sucic_kdfX963(unsigned char* sharedkey, size_t sharedkey_sz,
            unsigned char* sharedinfo, size_t sharedinfo_sz,
            unsigned char** retout, int out_sz);

int sucic_unpackDerivedKeys(unsigned char* data, unsigned char* aes_key, unsigned char* aes_nonce,
                            unsigned long long* aes_cnt, unsigned char* mac_key);

// https://medium.com/@zlhk100/openssl-for-iot-system-security-development-series-part-2-how-to-convert-raw-nist-secp256r1-f8f0939aa6d3
// echo 30310201010420F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDAa00a06082a8648ce3d030107 | xxd -r -p > ec-priv-hnkey.der

uint8_t hn_privkey_bytes[51] = {
        0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20,           // header
        0xF1, 0xAB, 0x10, 0x74, 0x47, 0x7E, 0xBC, 0xC7,     // key
        0xF5, 0x54, 0xEA, 0x1C, 0x5F, 0xC3, 0x68, 0xB1,
        0x61, 0x67, 0x30, 0x15, 0x5E, 0x00, 0x41, 0xAC,
        0x44, 0x7D, 0x63, 0x01, 0x97, 0x5F, 0xEC, 0xDA,
        0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,     // OID params indicate secp256r1
        0x3d, 0x03, 0x01, 0x07
};

uint8_t priv_bytes[512] = { //32
    0xF1, 0xAB, 0x10, 0x74, 0x47, 0x7E, 0xBC, 0xC7,
    0xF5, 0x54, 0xEA, 0x1C, 0x5F, 0xC3, 0x68, 0xB1,
    0x61, 0x67, 0x30, 0x15, 0x5E, 0x00, 0x41, 0xAC,
    0x44, 0x7D, 0x63, 0x01, 0x97, 0x5F, 0xEC, 0xDA
};

int priv_bytes_len = 32;

/*uint8_t suci_uepubkey_bytes[512] = { //33
        0x03, 0x08, 0x25, 0x5c, 0xd6, 0x3e, 0x72, 0x78,
        0xf0, 0x35, 0x32, 0x04, 0x2f, 0x99, 0xfb, 0x6e,
        0xb2, 0x8e, 0x3a, 0xab, 0x4a, 0x86, 0xe5, 0x4c,
        0xfe, 0xb8, 0xd1, 0xe2, 0xcf, 0xc1, 0x66, 0x50,
        0x69
};

int suci_uepubkey_bytes_len = 33;*/

// https://www.ietf.org/rfc/rfc5480.txt
// echo 3039301306072A8648CE3D020106082A8648CE3D030107032200039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1 | xxd -r -p > ec-pub-uekeysample.der
uint8_t ue_pubkey_bytes[39] = {
//        0x30, 0x59,           // uncompressed total = 91
        0x30, 0x39,     // compressed total = 39
        0x30, 0x13, 0x06, 0x07,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08,
        0x2A, 0x86, 0x48,0xCE,0x3D, 0x03, 0x01,  // ECC: 2A 86 48 CE 3D 02 01
        0x07, 0x03,
//        0x42, 0x00,           // header len uncompressed plus 0x00
        0x22, 0x00,     // header len compressed plus 0x00

/*        0x04, 0x9A, 0xAB, 0x83, 0x76, 0x59, 0x70, 0x21,   // key uncompressed
        0xE8, 0x55, 0x67, 0x9A, 0x97, 0x78, 0xEA, 0x0B,
        0x67, 0x39, 0x6E, 0x68, 0xC6, 0x6D, 0xF3, 0x2C,
        0x0F, 0x41, 0xE9, 0xAC, 0xCA, 0x2D, 0xA9, 0xB9,
        0xD1, 0xD1, 0xF4, 0x4E, 0xA1, 0xC8, 0x7A, 0xA7,
        0x47, 0x8B, 0x95, 0x45, 0x37, 0xBD, 0xE7, 0x99,
        0x51, 0xE7, 0x48, 0xA4, 0x32, 0x94, 0xA4, 0xF4,
        0xCF, 0x86, 0xEA, 0xFF, 0x17, 0x89, 0xC9, 0xC8,
        0x1F
*/
        0x03, 0x9A, 0xAB, 0x83, 0x76, 0x59, 0x70, 0x21,   // pubkey compressed sample
        0xE8, 0x55, 0x67, 0x9A, 0x97, 0x78, 0xEA, 0x0B,
        0x67, 0x39, 0x6E, 0x68, 0xC6, 0x6D, 0xF3, 0x2C,
        0x0F, 0x41, 0xE9, 0xAC, 0xCA, 0x2D, 0xA9, 0xB9,
        0xD1

/*        0x03, 0x08, 0x25, 0x5c, 0xd6, 0x3e, 0x72, 0x78,     // pubkey live device
        0xf0, 0x35, 0x32, 0x04, 0x2f, 0x99, 0xfb, 0x6e,
        0xb2, 0x8e, 0x3a, 0xab, 0x4a, 0x86, 0xe5, 0x4c,
        0xfe, 0xb8, 0xd1, 0xe2, 0xcf, 0xc1, 0x66, 0x50,
        0x69
        */
};

uint8_t ue_pubkey_rawbytes[33] = {
        0x03, 0x9A, 0xAB, 0x83, 0x76, 0x59, 0x70, 0x21,   // pubkey compressed sample
        0xE8, 0x55, 0x67, 0x9A, 0x97, 0x78, 0xEA, 0x0B,
        0x67, 0x39, 0x6E, 0x68, 0xC6, 0x6D, 0xF3, 0x2C,
        0x0F, 0x41, 0xE9, 0xAC, 0xCA, 0x2D, 0xA9, 0xB9,
        0xD1
};

void sucic_loadKeyData() {

    EVP_PKEY* hn_privkey = NULL;
    EVP_PKEY* ue_pubkey = NULL;

    HLOG("priv #1   ", hn_privkey_bytes, sizeof(hn_privkey_bytes));

    //hn_privkey = EVP_EC_gen("P-256");
    //ue_pubkey = EVP_EC_gen("P-256");

    // int res = sucic_loadPrivKeyBytes(&hn_privkey_bytes, sizeof(hn_privkey_bytes), &hn_privkey);
    int res = 0;

    hn_privkey = sucic_loadPrivateKeyFile("/home/chris/dev/sdr/sucic/ec-priv-hnkey.der", &hn_privkey);

//    if(res > 0 || hn_privkey == NULL) {
    if(hn_privkey == NULL) {
        printf("Unable to create Home Net keypair res=%d\n", res);
    } else {

        HLOG("priv #1b   ", hn_privkey_bytes, 512);//sizeof(hn_privkey_bytes));

        char curve_name[64];
        unsigned char pub[256];
        int len = 0;
        BIGNUM *bn_priv = NULL;

        if (!EVP_PKEY_get_utf8_string_param(hn_privkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                            curve_name, sizeof(curve_name), &len)) {
            ELOG("Error getting priv param\n");
        } else {
            ILOG("Got priv param curve name=%s\n", curve_name);
        }
        if (!EVP_PKEY_get_bn_param(hn_privkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv)) {
            ELOG("Error getting privkey\n");
        } else {
            ILOG("Got priv key\n");
        }

        HLOG("pub #1   ", ue_pubkey_bytes, sizeof(ue_pubkey_bytes));
        res = sucic_loadPubKeyBytes(&ue_pubkey_rawbytes, sizeof(ue_pubkey_rawbytes), &ue_pubkey);
//        ue_pubkey = sucic_loadPublicKeyFile("/home/chris/dev/sdr/sucic/ec-pub-uekeysample.der", &ue_pubkey);

        if(res > 0 || ue_pubkey == NULL) {
            ELOG("Unable to create UE pubkey res=%d\n", res);
        } else {
            if (!EVP_PKEY_get_utf8_string_param(ue_pubkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                                curve_name, sizeof(curve_name), &len)) {
                ELOG("Error getting pub param\n");
            } else {
                ILOG("Got pub param curve name=%s\n", curve_name);


                uint8_t tmpbuf[512];
                size_t tmplen = 66;
                res = EVP_PKEY_get_raw_public_key(ue_pubkey, &tmpbuf, &tmplen);
                if(res == 1) {
                    ILOG("Read pubkey from ue_pubkey len=%d\n", tmplen);

                } else {
                    ELOG("Failed to read pubkey from ue_pubkey res=%d\n", res);
                }

            }

            HLOG("pub #1b   ", ue_pubkey_bytes, sizeof(ue_pubkey_bytes));

            unsigned char* sharedkey = NULL;

            size_t sharedkey_len = 0;

            unsigned char* suci_sharedkey_bytes_ptr = &sharedkey;
            res = sucic_genSharedKey(hn_privkey, ue_pubkey, &sharedkey, &sharedkey_len); //sizeof(suci_ciphertext_bytes));

            ILOG("shared res=%d shared keylen=%d\n", res, sharedkey_len);

            if(!res && sharedkey != NULL) {
                HLOG("shared #1   ", sharedkey, sharedkey_len); //sizeof(suci_sharedkey_bytes));
            } else {
                ELOG("Unable to gen shared key res=%d\n", res);
            }

            uint8_t derived_keys[64];
            unsigned char* derived_keys_ptr = &derived_keys;

            res = sucic_kdfX963(sharedkey, sharedkey_len, &ue_pubkey_rawbytes, sizeof(ue_pubkey_rawbytes),
                                &derived_keys_ptr, sizeof(derived_keys));

            HLOG("derived #1   ", derived_keys, sizeof(derived_keys));

            if(res <= 0) {
                ELOG("Unable to derive key material\n");
            } else {

                uint8_t aes_key[16];
                uint8_t aes_nonce[16];
                uint64_t aes_cnt = 0;
                uint8_t mac_key[32];

                res = sucic_unpackDerivedKeys(&derived_keys, &aes_key, &aes_nonce,
                                           &aes_cnt, &mac_key);

                if(res != 0) {
                    ELOG("Unpack error res=%d\n", res);
                } else {
                    ILOG("Unpacked cnt=%llu\n", aes_cnt);
                    HLOG("derived aes_key #1   ", aes_key, sizeof(aes_key));
                    HLOG("derived aes_nonce #1   ", aes_nonce, sizeof(aes_nonce));
                    HLOG("derived mac #1   ", mac_key, sizeof(mac_key));

                    unsigned char ciphertext[5] = {
                            0x46, 0xA3, 0x3F, 0xC2, 0x71
                    };
                    unsigned char plaintext[32];
                    int plaintext_len = 0;

                    res = sucic_decrypt(ciphertext, sizeof(ciphertext), aes_key, aes_nonce, &plaintext, &plaintext_len);

                    if(res != 0) {
                        ELOG("Error decrypting SUCI res=%d\n", res);
                    } else {
                        HLOG("decrypted SUCI #1   ", plaintext, plaintext_len);
                    }
                }
            }
            EVP_PKEY_free(ue_pubkey);
        }
        EVP_PKEY_free(hn_privkey);
    }
}

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

int sucic_genSharedKey(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** sharedkey, size_t* secret_len) {

    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    size_t buf_len = 0;

    /* Create the context for the shared secret derivation */
    if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) { ret = 1; }

    /* Initialise */
    if(!ret && 1 != EVP_PKEY_derive_init(ctx)) { ret = 2; }

    //if(!ret && 1 != EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1)) { ret = 7; }

    /* Provide the peer public key */
    if(!ret && 1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) { ret = 3; }

    /* Determine buffer length for shared secret */
    //if(!ret && 1 != EVP_PKEY_derive(ctx, NULL, &buf_len)) { ret = 4; }
    if(!ret && 1 != EVP_PKEY_derive(ctx, NULL, secret_len)) { ret = 4; }

    printf("Keylen will be=%d\n", *secret_len); //buf_len); //

    unsigned char* sharedkeyloc = NULL;
    /* Create the buffer */
    if(!ret && NULL == (sharedkeyloc = OPENSSL_malloc(*secret_len))) { ret = 5; }
    //if(!ret && NULL == ((*sharedkey) = OPENSSL_malloc(*secret_len))) { ret = 5; }

    /* Derive the shared secret */
    //if(!ret && 1 != (EVP_PKEY_derive(ctx, *sharedkey, &buf_len))) {  ret = 6; }
    if(!ret && 1 != (EVP_PKEY_derive(ctx, sharedkeyloc, secret_len))) {  ret = 6; }

    //HLOG("sharedloc #1   ", sharedkeyloc, buf_len);

    //*secret_len = buf_len;
    HLOG("shared #1a   ", sharedkeyloc, *secret_len); //sizeof(suci_sharedkey_bytes));

    *sharedkey = sharedkeyloc;

    return ret;
}

/**
    https://github.com/P1sec/CryptoMobile/blob/master/CryptoMobile/EC.py#L133
    https://www.openssl.org/docs/manmaster/man7/EVP_KDF-X963.html
*/
int sucic_kdfX963(unsigned char* sharedkey, size_t sharedkey_sz,
             unsigned char* sharedinfo, size_t sharedinfo_sz,
             unsigned char** retout, int out_sz) {

    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    //unsigned char out[64];
    OSSL_PARAM params[4], *p = params;

    kdf = EVP_KDF_fetch(NULL, "X963KDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                             sharedkey, sharedkey_sz);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                             sharedinfo, sharedinfo_sz);
    *p = OSSL_PARAM_construct_end();

    int res = EVP_KDF_derive(kctx, *retout, out_sz, params);
    if(res <= 0) {
        ELOG("EVP_KDF_derive err=%d\n", res);
    } else {
        ELOG("EVP_KDF_derive success=%d\n", res);
    }

    EVP_KDF_CTX_free(kctx);

    return res;
};

int sucic_unpackDerivedKeys(unsigned char* data, unsigned char* aes_key, unsigned char* aes_nonce,
                            unsigned long long* aes_cnt, unsigned char* mac_key) {

    for(int i=0; i<16; i++) {
        aes_key[i] = data[i];
    }
    for(int i=0; i<16; i++) {
        aes_nonce[i] = data[i + 16];
    }
    union number
    {
        uint8_t charNum[8];
        uint64_t longNum;
    } cnt_num;

    for(int i=0; i<8; i++) {
        cnt_num.charNum[i] = data[i + 32];
    }
    //ILOG("Counter=%llu\n", cnt_num.longNum); //(unsigned long)(*(unsigned long*) cnt) );
    *aes_cnt = cnt_num.longNum;

    for(int i=0; i<32; i++) {
        mac_key[i] = data[i + 32];
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

// https://github.com/openssl/openssl/issues/16989
int sucic_loadPrivKeyBytes(uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey) {
    return sucic_loadKeyBytes(1, priv_bytes, priv_bytes_len, privkey);
}

int sucic_loadPubKeyBytes(uint8_t* pub_bytes, int priv_bytes_len, EVP_PKEY** pubkey) {
    return sucic_loadKeyBytes(0, pub_bytes, priv_bytes_len, pubkey);
}

int sucic_loadKeyBytes(short is_privkey, uint8_t* priv_bytes, int priv_bytes_len, EVP_PKEY** privkey) {


    unsigned char* key_buf = OPENSSL_malloc(1000); // surely enough

    for(int i=0; i<priv_bytes_len; i++) {
        key_buf[i] = priv_bytes[i];
    }
    const unsigned char* key_buf_ptr = key_buf;
    const unsigned char* pk_enc = priv_bytes; //pubkey_enc;
    //*privkey = EVP_EC_gen("P-256");
    HLOG("priv #2   ", priv_bytes, priv_bytes_len);
    *privkey = sucic_setECParams(*privkey, NID_X9_62_prime256v1);
    //int pubklen
    EVP_PKEY* privkeyloc = is_privkey ?
            d2i_PrivateKey(EVP_PKEY_EC, privkey, &key_buf, priv_bytes_len) //&priv_bytes)
            : d2i_PublicKey(EVP_PKEY_EC, privkey, &key_buf_ptr, priv_bytes_len); //&priv_bytes);
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
    HLOG("priv #4   ", pk_enc, priv_bytes_len);

//    OPENSSL_free(key_buf);

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

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message

int sucic_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int* plaintext_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int res = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) { res = 1; }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(!res && 1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) { res = 2; }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(!res && 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) { res = 3; }
    *plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(!res && 1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) { res = 4; }
    *plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return res;
}
