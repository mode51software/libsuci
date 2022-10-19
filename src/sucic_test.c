#ifdef SUCIC_TEST_ENABLED

#include <stdio.h>

#include "sucic_test.h"
#include "sucic_calcs.h"

int main() {
    printf("SUCI\n");
    sucic_deconceal(TEST_PRIV_HNKEY_FILE,
                    &ue_pubkey_rawbytes_test, sizeof(ue_pubkey_rawbytes_test),
                    &profileb_ciphertext_test, sizeof(profileb_ciphertext_test));
    return 0;
}
#endif // SUCIC_TEST_ENABLED
