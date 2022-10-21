
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <core_names.h>
#include <kdf.h>

#include "sucic_calcs.h"
#include "sucic_utils.h"

#ifdef SUCIC_TEST_ENABLED
#include "sucic_test.h"
#include "sucic_calcs.h"

#endif // SUCIC_TEST_ENABLED

// https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

int sucic_genSharedKey(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** secret, size_t* secret_len);
int sucic_kdfX963(unsigned char* sharedkey, size_t sharedkey_sz,
                  unsigned char* sharedinfo, size_t sharedinfo_sz,
                  unsigned char** retout, int out_sz);
int sucic_unpackDerivedKeys(unsigned char* data,
                            unsigned char* aes_key, unsigned char* aes_nonce, unsigned char* mac_key);
int sucic_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                  unsigned char *iv, unsigned char *plaintext, size_t* plaintext_len);


short sucic_deconceal(//uint8_t * privkeyder_filename,
                    EVP_PKEY* hn_privkey,
                    uint8_t* ue_pubkey_rawbytes, size_t ue_pubkey_rawbytes_sz,
                    uint8_t* profileb_ciphertext, size_t profileb_ciphertext_sz,
                    uint8_t* plaintext, size_t* plaintext_len) {

    //EVP_PKEY* hn_privkey = NULL;
    EVP_PKEY* ue_pubkey = NULL;

    // int res = sucic_loadPrivKeyBytes(&hn_privkey_bytes, sizeof(hn_privkey_bytes), &hn_privkey);
    int res = 0;

    //hn_privkey = sucic_loadPrivateKeyFile(privkeyder_filename, &hn_privkey);

//    if(res > 0 || hn_privkey == NULL) {
    if(hn_privkey == NULL) {
        printf("Unable to create Home Net privkey res=%d\n", res);
        return SUCIC_PRIVKEYNOTLOADED;
    } else {

        //HLOG("priv #1b   ", hn_privkey_bytes, 512);//sizeof(hn_privkey_bytes));

        /*char curve_name[64];
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
        }*/

        //HLOG("pub #1   ", ue_pubkey_bytes, sizeof(ue_pubkey_bytes));
        res = sucic_loadPubKeyBytes(ue_pubkey_rawbytes, ue_pubkey_rawbytes_sz, &ue_pubkey);
//        ue_pubkey = sucic_loadPublicKeyFile("/home/chris/dev/sdr/sucic/ec-pub-uekeysample.der", &ue_pubkey);

        if(res > 0 || ue_pubkey == NULL) {
            ELOG("Unable to create UE pubkey res=%d\n", res);
        } else {
            /*if (!EVP_PKEY_get_utf8_string_param(ue_pubkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                                curve_name, sizeof(curve_name), &len)) {
                ELOG("Error getting pub param\n");
            } else {
                ILOG("Got pub param curve name=%s\n", curve_name);
            }*/

            //HLOG("pub #1b   ", ue_pubkey_bytes, sizeof(ue_pubkey_bytes));

            unsigned char* sharedkey = NULL;

            size_t sharedkey_len = 0;

            unsigned char* suci_sharedkey_bytes_ptr = &sharedkey;
            res = sucic_genSharedKey(hn_privkey, ue_pubkey, &sharedkey, &sharedkey_len); //sizeof(suci_ciphertext_bytes));

            ILOG("shared res=%d shared keylen=%d\n", res, sharedkey_len);

            if(!res && sharedkey != NULL) {
                HLOG("shared #1   ", sharedkey, sharedkey_len); //sizeof(suci_sharedkey_bytes));
            } else {
                ELOG("Unable to gen shared key res=%d\n", res);
                return;
            }

            uint8_t derived_keys[64];
            unsigned char* derived_keys_ptr = &derived_keys;

            res = sucic_kdfX963(sharedkey, sharedkey_len, ue_pubkey_rawbytes, ue_pubkey_rawbytes_sz,
                                &derived_keys_ptr, sizeof(derived_keys));

            HLOG("derived #1   ", derived_keys, sizeof(derived_keys));

            if(sharedkey_len > 0) {
                OPENSSL_free(sharedkey);
            }

            if(res <= 0) {
                ELOG("Unable to derive key material\n");
            } else {

                uint8_t aes_key[16];
                uint8_t aes_nonce[16];
                uint8_t mac_key[32];

                res = sucic_unpackDerivedKeys(&derived_keys, &aes_key, &aes_nonce,&mac_key);

                if(res != 0) {
                    ELOG("Unpack error res=%d\n", res);
                } else {
                    HLOG("derived aes_key #1   ", aes_key, sizeof(aes_key));
                    HLOG("derived aes_nonce #1   ", aes_nonce, sizeof(aes_nonce));
                    HLOG("derived mac #1   ", mac_key, sizeof(mac_key));

                    res = sucic_decrypt(profileb_ciphertext, profileb_ciphertext_sz,
                                        aes_key, aes_nonce, plaintext, plaintext_len);

                    if(res != 0) {
                        ELOG("Error decrypting SUCI res=%d\n", res);
                    } else {
                        HLOG("decrypted SUCI #1   ", plaintext, *plaintext_len);
                        return SUCIC_OK;
                    }
                }
            }
            EVP_PKEY_free(ue_pubkey);
        }
        EVP_PKEY_free(hn_privkey);
    }
    return res;
}

int sucic_genSharedKey(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** sharedkey, size_t* secret_len) {

    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

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

    DLOG("Keylen will be=%d\n", *secret_len); //buf_len); //

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
                            unsigned char* mac_key) {

    for(int i=0; i<16; i++) {
        aes_key[i] = data[i];
    }
    for(int i=0; i<16; i++) {
        aes_nonce[i] = data[i + 16];
    }

    for(int i=0; i<32; i++) {
        mac_key[i] = data[i + 32];
    }

    return 0;
}

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message

int sucic_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, size_t* plaintext_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int res = 0;

    if(!(ctx = EVP_CIPHER_CTX_new())) { res = 1; }

    if(!res && 1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) { res = 2; }

    if(!res && 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) { res = 3; }
    *plaintext_len = len;

    if(!res && 1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) { res = 4; }
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return res;
}
