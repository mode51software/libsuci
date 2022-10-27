#ifdef SUCIC_TEST_ENABLED

#ifndef SUCIC_TEST_H
#define SUCIC_TEST_H

#include <stdint.h>

// https://medium.com/@zlhk100/openssl-for-iot-system-security-development-series-part-2-how-to-convert-raw-nist-secp256r1-f8f0939aa6d3
// echo 30310201010420F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDAa00a06082a8648ce3d030107 | xxd -r -p > ec-priv-hnkey.der

// https://www.ietf.org/rfc/rfc5480.txt
// echo 3039301306072A8648CE3D020106082A8648CE3D030107032200039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1 | xxd -r -p > ec-pub-uekeysample.der

#define TEST_PRIV_HNKEY_FILE "res/ec-priv-hnkey.der"

static uint8_t ue_pubkey_rawbytes_test[33] = {
        0x03, 0x9A, 0xAB, 0x83, 0x76, 0x59, 0x70, 0x21,   // pubkey compressed sample
        0xE8, 0x55, 0x67, 0x9A, 0x97, 0x78, 0xEA, 0x0B,
        0x67, 0x39, 0x6E, 0x68, 0xC6, 0x6D, 0xF3, 0x2C,
        0x0F, 0x41, 0xE9, 0xAC, 0xCA, 0x2D, 0xA9, 0xB9,
        0xD1
};

static unsigned char profileb_ciphertext_test[] = {
        0x46, 0xA3, 0x3F, 0xC2, 0x71
};

static unsigned char profileb_suci_text[] =
        "suci-0-001-01-0000-2-27-03adb356a7fce38f13c1f3e66db88b6171b9ae7023541e6ef28cf0463ddb75176b221155b883f9ea97e6ae680b3a";

#endif // SUCIC_TEST_H

#endif // SUCIC_TEST_ENABLED