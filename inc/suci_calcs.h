//
// Created by chris on 05/10/22.
//

#ifndef SUCIC_CALCS_H
#define SUCIC_CALCS_H

#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>

enum suci_res {
    SUCIC_OK,
    SUCIC_PRIVKEYNOTLOADED,
    SUCIC_PUBKEYNOTLOADED,
    SUCIC_DECRYPTFAILED,
    SUCIC_GENSHAREDFAILED,
    SUCIC_DERIVEFAILED,
    SUCIC_UNPACKFAILED,
    SUCIC_UEPUBKEYFAILED
};

struct rawSuciData {
    uint8_t*     ue_key;
    uint         ue_key_sz;
    uint8_t*     mac_key;
    uint         mac_key_sz;
    uint8_t*     enc_msin;
    uint         enc_msin_sz;
} typedef SuciData;

short suci_deconceal(EVP_PKEY* hn_privkey,
                     uint8_t* ue_pubkey_rawbytes, size_t ue_pubkey_rawbytes_sz,
                     uint8_t* profileb_ciphertext, size_t profileb_ciphertext_sz,
                     uint8_t* plaintext, size_t* plaintext_len);

#endif // SUCIC_CALCS_H
