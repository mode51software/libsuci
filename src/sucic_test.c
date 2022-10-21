#ifdef SUCIC_TEST_ENABLED

#include <stdio.h>
#include <types.h>

#include "sucic_test.h"
#include "sucic_calcs.h"
#include "sucic_utils.h"

int main() {

    printf("SUCI\n");

    uint8_t plaintext[32];
    size_t plaintext_len = 0;
    EVP_PKEY* hn_privkey;

    hn_privkey = sucic_loadPrivateKeyFile(TEST_PRIV_HNKEY_FILE, &hn_privkey);

    sucic_deconceal(hn_privkey,
                    &ue_pubkey_rawbytes_test, sizeof(ue_pubkey_rawbytes_test),
                    &profileb_ciphertext_test, sizeof(profileb_ciphertext_test),
                    &plaintext, &plaintext_len);
    return 0;
}
#endif // SUCIC_TEST_ENABLED
