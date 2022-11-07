
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>

#include "suci_calcs.h"
#include "suci_utils.h"

#ifdef SUCIC_TEST_ENABLED
#include "suci_test.h"
#include "suci_calcs.h"

#endif // SUCIC_TEST_ENABLED

// https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

int sucic_genSharedKey(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** secret, size_t* secret_len);
int suci_kdfX963(unsigned char* sharedkey, size_t sharedkey_sz,
                  unsigned char* sharedinfo, size_t sharedinfo_sz,
                  unsigned char** retout, int out_sz);
int suci_unpackDerivedKeys(unsigned char* data,
                            unsigned char* aes_key, unsigned char* aes_nonce, unsigned char* mac_key);
int suci_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                  unsigned char *iv, unsigned char *plaintext, size_t* plaintext_len);


short suci_deconceal(//uint8_t * privkeyder_filename,
                    EVP_PKEY* hn_privkey,
                    uint8_t* ue_pubkey_rawbytes, size_t ue_pubkey_rawbytes_sz,
                    uint8_t* profileb_ciphertext, size_t profileb_ciphertext_sz,
                    uint8_t* plaintext, size_t* plaintext_len) {

    EVP_PKEY* ue_pubkey = NULL;

    int res = 0;

    if(hn_privkey == NULL) {
        ELOG("Unable to create Home Net privkey res=%d\n", res);
        return SUCIC_PRIVKEYNOTLOADED;
    } else {

        res = suci_loadPubKeyBytes(ue_pubkey_rawbytes, ue_pubkey_rawbytes_sz, &ue_pubkey);

        if(res > 0 || ue_pubkey == NULL) {
            ELOG("Unable to create UE pubkey res=%d\n", res);
            return SUCIC_UEPUBKEYFAILED;
        } else {

            unsigned char* sharedkey = NULL;

            size_t sharedkey_len = 0;

            unsigned char* suci_sharedkey_bytes_ptr = &sharedkey;
            res = sucic_genSharedKey(hn_privkey, ue_pubkey, &sharedkey, &sharedkey_len); //sizeof(suci_ciphertext_bytes));

            ILOG("shared res=%d shared keylen=%d\n", res, sharedkey_len);

            if(!res && sharedkey != NULL) {
                HLOG("shared #1   ", sharedkey, sharedkey_len); //sizeof(suci_sharedkey_bytes));

                uint8_t derived_keys[64];
                unsigned char* derived_keys_ptr = &derived_keys;

                res = suci_kdfX963(sharedkey, sharedkey_len, ue_pubkey_rawbytes, ue_pubkey_rawbytes_sz,
                                   &derived_keys_ptr, sizeof(derived_keys));

                HLOG("derived #1   ", derived_keys, sizeof(derived_keys));

                if(sharedkey_len > 0) {
                    OPENSSL_free(sharedkey);
                }

                if(res <= 0) {
                    ELOG("Unable to derive key material\n");
                    res = SUCIC_DERIVEFAILED;
                } else {

                    uint8_t aes_key[16];
                    uint8_t aes_nonce[16];
                    uint8_t mac_key[32];

                    res = suci_unpackDerivedKeys(&derived_keys, &aes_key, &aes_nonce,&mac_key);

                    if(res != 0) {
                        ELOG("Unpack error res=%d\n", res);
                        res = SUCIC_UNPACKFAILED;
                    } else {
                        HLOG("derived aes_key #1   ", aes_key, sizeof(aes_key));
                        HLOG("derived aes_nonce #1   ", aes_nonce, sizeof(aes_nonce));
                        HLOG("derived mac #1   ", mac_key, sizeof(mac_key));

                        res = suci_decrypt(profileb_ciphertext, profileb_ciphertext_sz,
                                           aes_key, aes_nonce, plaintext, plaintext_len);

                        if(res != 0) {
                            ELOG("Error decrypting SUCI res=%d\n", res);
                            res = SUCIC_DECRYPTFAILED;
                        } else {
                            HLOG("decrypted SUCI #1   ", plaintext, *plaintext_len);
                            res = SUCIC_OK;
                        }
                    }
                }

            } else {
                ELOG("Unable to gen shared key res=%d\n", res);
                res = SUCIC_GENSHAREDFAILED;
            }

            EVP_PKEY_free(ue_pubkey);
        }
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
    if(!ret && 1 != EVP_PKEY_derive(ctx, NULL, secret_len)) { ret = 4; }

    DLOG("Keylen will be=%d\n", *secret_len); //buf_len); //

    unsigned char* sharedkeyloc = NULL;
    /* Create the buffer */
    if(!ret && NULL == (sharedkeyloc = OPENSSL_malloc(*secret_len))) { ret = 5; }

    /* Derive the shared secret */
    if(!ret && 1 != (EVP_PKEY_derive(ctx, sharedkeyloc, secret_len))) {  ret = 6; }

    HLOG("shared #1a   ", sharedkeyloc, *secret_len); //sizeof(suci_sharedkey_bytes));

    *sharedkey = sharedkeyloc;

    EVP_PKEY_CTX_free(ctx);

    return ret;
}

/**
    https://www.openssl.org/docs/manmaster/man7/EVP_KDF-X963.html
*/
int suci_kdfX963(unsigned char* sharedkey, size_t sharedkey_sz,
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

int suci_unpackDerivedKeys(unsigned char* data, unsigned char* aes_key, unsigned char* aes_nonce,
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

int suci_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, size_t* plaintext_len) {
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
