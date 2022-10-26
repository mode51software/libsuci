#ifdef SUCIC_TEST_ENABLED

#include <stdio.h>
#include <types.h>
#include <string.h>

#include "sucic_test.h"
#include "sucic_calcs.h"
#include "sucic_utils.h"

int main() {

    printf("SUCI\n");

    uint8_t plaintext[32];
    size_t plaintext_len = 0;
    EVP_PKEY* hn_privkey;
    SuciData* rawSuciData;

    hn_privkey = sucic_loadPrivateKeyFile(TEST_PRIV_HNKEY_FILE, &hn_privkey);

    rawSuciData = malloc(sizeof(SuciData));

#define MAX_SUCI_TOKEN 16
    char* array[MAX_SUCI_TOKEN];
    int i = 0;
    unsigned char profileb_suci_text[] =
            "suci-0-001-01-0000-2-27-03adb356a7fce38f13c1f3e66db88b6171b9ae7023541e6ef28cf0463ddb75176b221155b883f9ea97e6ae680b3a";
    unsigned char* p = &profileb_suci_text;
    while((array[i++] = strsep(&p, "-"))) {
        //
    }

    sucic_unpackSuciString(array[7], rawSuciData, 33);

    //sucic_unpackRawSuciBytes(profileb_rawsucibytes, sizeof(profileb_rawsucibytes),
    //                         rawSuciData, 33);

    /*sucic_deconceal(hn_privkey,
                    &ue_pubkey_rawbytes_test, sizeof(ue_pubkey_rawbytes_test),
                    &profileb_ciphertext_test, sizeof(profileb_ciphertext_test),
                    &plaintext, &plaintext_len); */

    sucic_deconceal(hn_privkey,
                    rawSuciData->ue_key, rawSuciData->ue_key_sz,
                    rawSuciData->enc_msin, rawSuciData->enc_msin_sz,
                    &plaintext, &plaintext_len);

    uint8_t* plaintext_str = (uint8_t*) malloc((plaintext_len * 2) + 1);
    sucic_sprintfHex(&plaintext, plaintext_str, plaintext_len, 1);
    ILOG("plaintext_str=%s\n", plaintext_str);
    free(plaintext_str);

    sucic_cleanupSuciData(rawSuciData);

    return 0;
}
#endif // SUCIC_TEST_ENABLED
