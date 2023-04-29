#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void decrypt(BIGNUM *C, BIGNUM *d, BIGNUM *n, char **result_str)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M = BN_new();

    // Decrypt the message using the private key (d, n)
    BN_mod_exp(M, C, d, n, ctx);

    // Convert the decrypted message to a hexadecimal string
    *result_str = BN_bn2hex(M);

    // Convert the hexadecimal string back to an ASCII string
    char *message_str = (char *)malloc(strlen(*result_str) / 2 + 1);
    int i;
    for (i = 0; i < strlen(*result_str) / 2; i++)
        sscanf(*result_str + i * 2, "%02X", message_str + i);
    message_str[strlen(*result_str) / 2] = '\0';

    printf("Decrypted message: %s\n", message_str);

    // Free memory
    BN_free(M);
    BN_CTX_free(ctx);
    free(message_str);
}

int main()
{
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Initialize n, e, d to the given values
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Convert the ciphertext to a BIGNUM
    BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Decrypt the message using the private key (d, n)
    char *result_str;
    decrypt(C, d, n, &result_str);

    // Free memory
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(M);
    BN_free(C);

    return 0;
}
