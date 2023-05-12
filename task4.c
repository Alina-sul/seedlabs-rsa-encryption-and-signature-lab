#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void sign_message(BIGNUM *M, BIGNUM *d, BIGNUM *n, char **result_str)
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *S = BN_new();

  // Sign the message using the private key (d, n)
  BN_mod_exp(S, M, d, n, ctx);

  // Convert the signed message to a hexadecimal string
  *result_str = BN_bn2hex(S);

  // Print the signed message
  printf("Signed message: %s\n", *result_str);

  // Free memory
  BN_free(S);
  BN_CTX_free(ctx);
}

int main()
{
  BIGNUM *n = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *M = BN_new();
  BIGNUM *M2 = BN_new();

  // Initialize n, d to the given values
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  // Convert the messages to a hexadecimal string
  char *message_str = "I owe you $2000.";
  char *message_str2 = "I owe you $3000.";

  char *hex_str = (char*) malloc(strlen(message_str) * 2 + 1);
  char *hex_str2 = (char*) malloc(strlen(message_str2) * 2 + 1);
  int i;
  for (i = 0; i < strlen(message_str); i++)
    sprintf(hex_str + i * 2, "%02X", message_str[i]);
  for (i = 0; i < strlen(message_str2); i++)
    sprintf(hex_str2 + i * 2, "%02X", message_str2[i]);

  // Convert the hexadecimal strings to BIGNUMs
  BN_hex2bn(&M, hex_str);
  BN_hex2bn(&M2, hex_str2);
  free(hex_str);
  free(hex_str2);

  // Sign the messages using the private key (d, n)
  char *result_str;
  sign_message(M, d, n, &result_str);
  sign_message(M2, d, n, &result_str);

  // Free memory
  BN_free(n);
  BN_free(d);
  BN_free(M);
  BN_free(M2);
  return 0;
}
