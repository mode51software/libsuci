//
// Created by chris on 05/10/22.
//

#ifndef SUCIC_SUCIC_CALCS_H
#define SUCIC_SUCIC_CALCS_H

#include <stdint.h>
#include <stdio.h>

void sucic_deconceal(unsigned char *privkeyder_filename,
                     uint8_t *ue_pubkey_rawbytes, size_t ue_pubkey_rawbytes_sz,
                     uint8_t *profileb_ciphertext, size_t profileb_ciphertext_sz);


#endif //SUCIC_SUCIC_CALCS_H
