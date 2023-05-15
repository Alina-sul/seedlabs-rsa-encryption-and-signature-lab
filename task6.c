#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

void printBN(char *msg, BIGNUM * a)
{
  /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

int main()
{
  // Step 1: Gathering the required data
  // This step involves reading the public key, signature and certificate body from files.
  // The following are placeholders, you should replace them with your actual data.
  char *e = "010001";  // Public exponent (part of public key)
  char *n = "F588DFE7628C1E37F83742907F6C87D0FB658225FDE8CB6BA4FF6DE95A23E299F61CE9920399137C090A8AFA42D65E5624AA7A33841FD1E969BBB974EC574C66689377375553FE39104DB734BB5F2577373B1794EA3CE59DD5BCC3B443EB2EA747EFB0441163D8B44185DD413048931BBFB7F6E0450221E0964217CFD92B6556340726040DA8FD7DCA2EEFEA487C374D3F009F83DFEF75842E79575CFC576E1A96FFFC8C9AA699BE25D97F962C06F7112A028080EB63183C504987E58ACA5F192B59968100A0FB51DBCA770B0BC9964FEF7049C75C6D20FD99B4B4E2CA2E77FD2DDC0BB66B130C8C192B179698B9F08BF6A027BBB6E38D518FBDAEC79BB1899D";  // Modulus (part of public key)
  char *S = "2dc3b65ce5e234baacf2f99f6465f6c190bb7f47bdf91cf4563f081b09d4c9bf732308b357e984b0b55b0dbc02286347fdd0a6221859634718b0348d195a532b63f1396ded4dc9cc294fdb704e4744d8d60541186243b03813e8fb9e7a3b36e567ab1d810fa1610142e653b313590aef6ba5df0f41c6bb7caf13d35bda7b1ec1eaef65fb26118ba3dd65fc8a9e690f291b992483ed715c336992ffba5174a0762ae0aaae2f02aeebc16326bcdd8f4eb17d9deff4b1317c454f9a9aee6dea1793b779600aa9ad9379546aa61b5df8a37c810737e8c9767969f71194205cdc7f92b280ccb47442253c567261ff68b4337b0351b8f920dea8439f74be0c1515f40e";  // CA's signature
  char *M = "30444d83ebcc1e1b932009d6610589e38b49bbcc0c83220e2f379469667cb61f";  // Certificate body

  // Step 2: Building the RSA public key
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *bn_e = BN_new();
  BIGNUM *bn_n = BN_new();
  BN_hex2bn(&bn_e, e);
  BN_hex2bn(&bn_n, n);

  // Step 3: Hashing the certificate's body
  // This should be done using the SHA-256 algorithm, and the result should be a BIGNUM
  // This is a placeholder, you should replace it with actual code to hash 'M'
  BIGNUM *hash = BN_new();
  BN_hex2bn(&hash, M);

  // Step 4: Decrypting the CA's signature
  BIGNUM *bn_S = BN_new();
  BIGNUM *decrypted_signature = BN_new();
  BN_hex2bn(&bn_S, S);
  BN_mod_exp(decrypted_signature, bn_S, bn_e, bn_n, ctx);

  // Step 5: Comparing the hashes
  if(BN_cmp(hash, decrypted_signature) == 0) {
    printf("Signature Valid\n");
  } else {
    printf("Signature Invalid\n");
  }

  // Cleanup
  BN_free(bn_e);
  BN_free(bn_n);
  BN_free(bn_S);
  BN_free(decrypted_signature);
  BN_free(hash);
  BN_CTX_free(ctx);

  return 0;
}
