//
// Created by chris on 05/10/22.
//

#ifndef SUCIC_SUCIC_CALCS_H
#define SUCIC_SUCIC_CALCS_H

#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>

enum sucic_res {
    SUCIC_OK,
    SUCIC_PRIVKEYNOTLOADED
};

short sucic_deconceal(EVP_PKEY* hn_privkey,
                     uint8_t* ue_pubkey_rawbytes, size_t ue_pubkey_rawbytes_sz,
                     uint8_t* profileb_ciphertext, size_t profileb_ciphertext_sz,
                     uint8_t* plaintext, size_t* plaintext_len);

#endif //SUCIC_SUCIC_CALCS_H
