#include <stdio.h>
#include <stdlib.h>

typedef struct
{
  uint32_t sk[32]; //  DES subkeys 
} mbedtls_des_context;

#define MBEDTLS_DES_KEY_SIZE						8
#define MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH        -0x0032  // The data input has an invalid length.
#define MBEDTLS_DES_ENCRYPT							1
#define MBEDTLS_DES_DECRYPT							0

void mbedtls_des_setkey(uint32_t SK[32], const unsigned char key[MBEDTLS_DES_KEY_SIZE]);

int mbedtls_des_setkey_dec(mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE]);


int mbedtls_des_crypt_cbc(mbedtls_des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output);

int mbedtls_des_crypt_ecb(mbedtls_des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8]);
