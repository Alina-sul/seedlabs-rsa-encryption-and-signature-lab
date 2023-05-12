#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void sign_and_verify_message(char *message_str, BIGNUM *d, BIGNUM *n, BIGNUM *e)
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

  // Sign the message using the private key (d, n)
  BN_mod_exp(S, M, d, n, ctx);

  // Print the signed message as a hexadecimal string
  char *signed_str = BN_bn2hex(S);
  printf("Signed message: %s\n", signed_str);

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
  BIGNUM *d = BN_new();

  // Initialize n, e, d to the given values
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  // Sign and verify the messages
  sign_and_verify_message("I owe you $2000.", d, n, e);
  sign_and_verify_message("I owe you $3000.", d, n, e);

  // Free memory
  BN_free(n);
  BN_free(e);
  BN_free(d);

  return 0;
}
