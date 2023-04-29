/* task1.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}


int main ()
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *etf_of_n = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *p_minus1 = BN_new();
  BIGNUM *q_minus1 = BN_new();
  
  // Initialize p, q, e
  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  // Calculate n = p * q
  BN_mul(n, p, q, ctx);
  printBN("n = ", n);
  
  // Calculate Euler's totient function of n: φ(n) = (p-1) * (q-1)
  BN_sub(p_minus1, p, BN_value_one());
  BN_sub(q_minus1, q, BN_value_one());
  BN_mul(etf_of_n, p_minus1, q_minus1, ctx);
  printBN("φ(n) = ", etf_of_n);

  // Calculate the modular multiplicative inverse of e modulo φ(n): d
  BN_mod_inverse(d, e, etf_of_n, ctx);
  printBN("d = ", d);

  // Free the allocated memory
  BN_free(p);
  BN_free(q);
  BN_free(e);
  BN_free(n);
  BN_free(etf_of_n);
  BN_free(d);
  BN_free(p_minus1);
  BN_free(q_minus1);
  BN_CTX_free(ctx);

  return 0;
}