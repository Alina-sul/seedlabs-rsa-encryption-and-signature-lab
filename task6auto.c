#include <stdio.h>
#include <openssl/bn.h>

// Function to print Big Numbers
void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

// Function to read a Big Number from a file
BIGNUM * readBNFromFile(char *filename)
{
  FILE *file = fopen(filename, "r");
  if (!file) {
    printf("Unable to open file %s\n", filename);
    exit(-1);
  }
  char hexNum[1024];
  fscanf(file, "%s", hexNum);
  fclose(file);
  BIGNUM *bn = BN_new();
  BN_hex2bn(&bn, hexNum);
  return bn;
}

int main() 
{
  // Variables declaration
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *M = BN_new();
  BIGNUM *H = BN_new();
  BIGNUM *S = BN_new();

  // Extract public key and signature from certificate
  system("openssl x509 -in /path/to/certificate.pem -noout -modulus > modulus.txt");
  system("openssl x509 -in /path/to/certificate.pem -noout -pubkey | openssl asn1parse -noout -inform pem -out public.key");
  system("openssl x509 -in /path/to/certificate.pem -noout -pubkey | openssl asn1parse -strparse 19 -out sig.txt");

  // Read the modulus and the signature from the files
  n = readBNFromFile("modulus.txt");
  S = readBNFromFile("sig.txt");

  // Compute the hash of the certificate body
  BN_hex2bn(&M, "30444d83ebcc1e1b932009d6610589e38b49bbcc0c83220e2f379469667cb61f");
  
  // Calculate H = S^e mod n, this should give us back the original hash of the message
  BN_mod_exp(H, S, e, n, ctx);

  // Truncate hash value to 256 bits
  BN_mask_bits(H, 256);

  // Print final information
  printBN("H (Hash from signature) =", H);
  printBN("M (Original message hash) =", M);

  if(BN_cmp(H, M) == 0) 
    printf("Signature Valid\n");
  else 
    printf("Signature Invalid\n");

  return 0;
}
