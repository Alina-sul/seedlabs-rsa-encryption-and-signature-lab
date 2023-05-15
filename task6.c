#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

// Function to print BIGNUM in hexadecimal format
void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    // Allocate necessary structures
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new(); // Public exponent
    BIGNUM *n = BN_new(); // Modulus for public key
    BIGNUM *S = BN_new(); // Signature
    BIGNUM *H = BN_new(); // Hash from the signature
    BIGNUM *M = BN_new(); // Provided message hash

    // Load values into BIGNUM structures
    BN_hex2bn(&e, "010001"); // Public exponent is usually 65537, or 0x10001 in hex
    // Modulus for public key
    BN_hex2bn(&n,"F588DFE7628C1E37F83742907F6C87D0FB658225FDE8CB6BA4FF6DE95A23E299F61CE9920399137C090A8AFA42D65E5624AA7A33841FD1E969BBB974EC574C66689377375553FE39104DB734BB5F2577373B1794EA3CE59DD5BCC3B443EB2EA747EFB0441163D8B44185DD413048931BBFB7F6E0450221E0964217CFD92B6556340726040DA8FD7DCA2EEFEA487C374D3F009F83DFEF75842E79575CFC576E1A96FFFC8C9AA699BE25D97F962C06F7112A028080EB63183C504987E58ACA5F192B59968100A0FB51DBCA770B0BC9964FEF7049C75C6D20FD99B4B4E2CA2E77FD2DDC0BB66B130C8C192B179698B9F08BF6A027BBB6E38D518FBDAEC79BB1899D");
    // Signature
    BN_hex2bn(&S,"2dc3b65ce5e234baacf2f99f6465f6c190bb7f47bdf91cf4563f081b09d4c9bf732308b357e984b0b55b0dbc02286347fdd0a6221859634718b0348d195a532b63f1396ded4dc9cc294fdb704e4744d8d60541186243b03813e8fb9e7a3b36e567ab1d810fa1610142e653b313590aef6ba5df0f41c6bb7caf13d35bda7b1ec1eaef65fb26118ba3dd65fc8a9e690f291b992483ed715c336992ffba5174a0762ae0aaae2f02aeebc16326bcdd8f4eb17d9deff4b1317c454f9a9aee6dea1793b779600aa9ad9379546aa61b5df8a37c810737e8c9767969f71194205cdc7f92b280ccb47442253c567261ff68b4337b0351b8f920dea8439f74be0c1515f40e")
    // Provided message hash
    BN_hex2bn(&M, "30444d83ebcc1e1b932009d6610589e38b49bbcc0c83220e2f379469667cb61f");

    // Compute: H = S^e mod n
    BN_mod_exp(H, S, e, n, ctx);

    // Truncate hash value to 256 bits
    BN_mask_bits(H, 256);

    // Print final information
    printBN("H (Computed hash) =", H);
    printBN("M (Provided hash) =", M);

    // Compare computed hash with provided hash
    if(BN_cmp(H, M) == 0)
      printf("Signature Valid\n");
    else
      printf("Signature Invalid\n");

    // Free allocated structures
    BN_CTX_free(ctx);
    BN_free(e);
    BN_free(n);
    BN_free(S);
    BN_free(H);
    BN_free(M);

    return 0;
}
