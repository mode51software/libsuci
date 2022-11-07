#ifdef SUCIC_TEST_ENABLED

#include <stdio.h>
#include <types.h>
#include <string.h>

#include "suci_test.h"
#include "suci_calcs.h"
#include "suci_utils.h"

#define UE_KEYSZ 33

void sucitest_profileBSampleData(EVP_PKEY* hn_privkey, uint8_t* plaintext, size_t* plaintext_len);
void sucitest_open5GS(EVP_PKEY* hn_privkey, SuciData* raw_sucidata, uint8_t* plaintext, size_t* plaintext_len);

int main() {

    ILOG("SUCI\n");

    uint8_t plaintext[32];
    size_t plaintext_len = 0;
    EVP_PKEY* hn_privkey;

    hn_privkey = suci_loadPrivateKeyFile(TEST_PRIV_HNKEY_FILE, &hn_privkey);

    sucitest_profileBSampleData(hn_privkey, (uint8_t *) &plaintext, &plaintext_len);

    // alternatively test in the way that Open5GS will use
    //SuciData* raw_sucidata;
    //raw_sucidata = malloc(sizeof(SuciData));
    //sucitest_open5GS(hn_privkey, raw_sucidata, &plaintext, &plaintext_len);
    //suci_cleanupSuciData(raw_sucidata);

    EVP_PKEY_free(hn_privkey);

    return 0;
}

void sucitest_profileBSampleData(EVP_PKEY* hn_privkey, uint8_t* plaintext, size_t* plaintext_len) {

    suci_deconceal(hn_privkey,
                   (uint8_t *) &ue_pubkey_rawbytes_test, sizeof(ue_pubkey_rawbytes_test),
                   (uint8_t *) &profileb_ciphertext_test, sizeof(profileb_ciphertext_test),
                   plaintext, plaintext_len);

    uint8_t* plaintext_str = (uint8_t*) malloc(((*plaintext_len) * 2) + 1);
    suci_sprintfHex(plaintext, plaintext_str, *plaintext_len, 0);
    ILOG("plaintext_str=%s\n", plaintext_str);
    free(plaintext_str);

}

void sucitest_open5GS(EVP_PKEY* hn_privkey, SuciData* raw_sucidata, uint8_t* plaintext, size_t* plaintext_len) {

    // how Open5GS UDM will access
    #define MAX_SUCI_TOKEN 16
    char* array[MAX_SUCI_TOKEN];
    int i = 0;
    unsigned char* p = &profileb_suci_text;
    while((array[i++] = strsep(&p, "-"))) {
        //
    }
    suci_unpackSuciString(array[7], raw_sucidata, UE_KEYSZ);


    suci_deconceal(hn_privkey,
                    raw_sucidata->ue_key, raw_sucidata->ue_key_sz,
                    raw_sucidata->enc_msin, raw_sucidata->enc_msin_sz,
                    plaintext, plaintext_len);

    uint8_t* plaintext_str = (uint8_t*) malloc(((*plaintext_len) * 2) + 1);
    suci_sprintfHex(plaintext, plaintext_str, *plaintext_len, 1);
    ILOG("plaintext_str=%s\n", plaintext_str);
    free(plaintext_str);

}

#endif // SUCIC_TEST_ENABLED
