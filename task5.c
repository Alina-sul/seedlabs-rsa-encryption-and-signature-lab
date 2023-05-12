#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void verify_signature(char *message_str, char *signature_str, BIGNUM *e, BIGNUM *n)
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *M = BN_new();
  BIGNUM *S = BN_new();

  // Convert the message to a hexadecimal string
  char *hex_str = (char*) malloc(strlen(message_str) * 2 + 1);
  int i;
  for (i = 0; i < strlen(message_str); i++)
    sprintf(hex_str + i * 2, "%02X", message_str[i]);

  // Convert the hexadecimal string to a BIGNUM
  BN_hex2bn(&M, hex_str);
  free(hex_str);

  // Convert the signature to a BIGNUM
  BN_hex2bn(&S, signature_str);

  // Verify the signature using the public key (e, n)
  BIGNUM *M2 = BN_new();
  BN_mod_exp(M2, S, e, n, ctx);

  // Convert the verified message to a hexadecimal string
  char *verified_str = BN_bn2hex(M2);

  // Convert the hexadecimal string back to an ASCII string
  char *message_str2 = (char*) malloc(strlen(verified_str) / 2 + 1);
  for (i = 0; i < strlen(verified_str) / 2; i++)
    sscanf(verified_str + i * 2, "%02X", message_str2 + i);
  message_str2[strlen(verified_str) / 2] = '\0';

  // Print the verified message
  printf("Verified message: %s\n", message_str2);

  // Check if the verified message matches the original
  if (strcmp(message_str, message_str2) == 0) {
    printf("The signature is valid.\n");
  } else {
    printf("The signature is invalid.\n");
  }

  // Free memory
  BN_free(M);
  BN_free(S);
  BN_free(M2);
  BN_CTX_free(ctx);
  free(message_str2);
}

int main()
{
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();

  // Initialize n, e to the given values
  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&e, "010001");

  // Verify the signatures
  verify_signature("Launch a missile.", "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F", e, n);
  verify_signature("Launch a missile.", "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F", e, n);

  // Free memory
  BN_free(n);
  BN_free(e);

  return 0;
}
