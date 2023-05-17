import argparse

from fractions import gcd

parser = argparse.ArgumentParser(description='RSA Common modulus attack')
required_named = parser.add_argument_group('required named arguments')
required_named.add_argument('-n', '--modulus', help='Common modulus', type=long, required=True)
required_named.add_argument('-e1', '--e1', help='First exponent', type=long, required=True)
required_named.add_argument('-e2', '--e2', help='Second exponent', type=long, required=True)
required_named.add_argument('-ct1', '--ct1', help='First ciphertext', type=long, required=True)
required_named.add_argument('-ct2', '--ct2', help='Second ciphertext', type=long, required=True)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    else:
        return x % m

def attack(c1, c2, e1, e2, N):
    if gcd(e1, e2) != 1:
        raise ValueError("Exponents e1 and e2 must be coprime")
    s1 = modinv(e1,e2)
    s2 = (gcd(e1,e2) - e1 * s1) / e2
    temp = modinv(c2, N)
    m1 = pow(c1,s1,N)
    m2 = pow(temp,-s2,N)
    return (m1 * m2) % N

def main():
    args = parser.parse_args()
    print '[+] Started attack...'
    try:
        message = attack(args.ct1, args.ct2, args.e1, args.e2, args.modulus)
        print '[+] Attack finished!'
        print '\nPlaintext message:\n%s' % format(message, 'x').decode('hex')
    except Exception as e:
        print '[+] Attack failed!'
        print e.message

main()