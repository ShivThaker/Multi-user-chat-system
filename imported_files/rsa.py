import random
import math


def computeGCD(x, y):
    gcd = 0
    if x > y:
        small = y
    else:
        small = x
    for i in range(1, small + 1):
        if (x % i == 0) and (y % i == 0):
            gcd = i
    return gcd


def coPrime(x):
    """
    Finds a random co-prime of given number for the value of 'e'

    n = x * 2 + 100000
    y = random.randint(x * 2, n)
    if computeGCD(x, y) != 1:
        return coPrime(x)
    else:
        return y
    """
    y = random.randint(4, x)
    if computeGCD(x, y) != 1:
        return coPrime(x)
    else:
        return y


def mod_inverse(base, m):
    """
    Calculates modular multiplicative inverse
    """
    g, x, y = mod_inverse_iterative(base, m)
    if g != 1:
        return None
    else:
        return x % m


def mod_inverse_iterative(a, b):
    """
    Works as Extended Euclid's algorithm
    """
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q = int(b / a)
        r = b % a
        m = x - u * q
        n = y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y


def modulo(a, b, c):
    return (int(a) ** int(b)) % int(c)


def totient(n):
    """
    Calculate Euler's totient
    Returns the number of integers less than or equal to
        that integer n that are relatively prime to it.
    """
    count = 0
    for i in range(1, n):
        if math.gcd(n, i) == 1:
            count += 1
    return count


def gen_prime():
    primes = []
    start = 11
    end = 25
    for i in range(start, end):
        if i > 1:
            for j in range(2, i):
                if i % j == 0:
                    break
            else:
                primes.append(i)
    # print(primes)
    return primes[random.randint(1, len(primes) - 1)]


def prime_factors(n):
    """
    Factorizes given prime number
    """
    factors = []
    lastresult = n
    c = 2
    while lastresult != 1:
        if lastresult % c == 0 and c % 2 > 0:
            factors.append(c)
            lastresult /= c
            c += 1
        else:
            c += 1
    return factors[0], factors[1]


def endecrypt(x, e, c):
    return modulo(x, e, c)


#######################################
def decode(x):
    try:
        return str(chr(x).encode('ascii', 'replace'))
    except ValueError as err:
        print(err)
        print("** ERROR - Decoded character is unrecognized **")


#######################################

def key_cracker(e, c):
    print(f"Public Key: ({e}, {c})")
    a, b = prime_factors(c)
    print(f"[a, b] : [{a}, {b}]")
    m = (a - 1) * (b - 1)
    print(f"Totient: {m}")
    d = mod_inverse(e, m)
    print(f'Private Key: ({d}, {c})')
    return d


def keygen():
    """
    Generates RSA keys
    """
    a = gen_prime()
    b = gen_prime()
    # print(a)
    # print(b)
    if a == b:
        keygen()

    c = a * b
    m = (a - 1) * (b - 1)
    e = coPrime(m)
    d = mod_inverse(e, m)
    if d is None:
        keygen()
    # print(f'd{d}')
    return e, d, c


def test_encryption(e, c):
    """
    Test function for encryption
    """
    message = input("Enter word to encrypt: ")
    ciphered = ''

    for i in range(0, len(message)):
        ciphered = f'{ciphered}{chr(endecrypt(ord(message[i]), e, c))}'

    print(ciphered + ' is the ciphered text')
    d = key_cracker(e, c)
    print("Plain text is:")
    for i in range(0, len(ciphered)):
        print(chr(endecrypt(ord(ciphered[i]), d, c)), end='')


"""
ee, dd, cc = keygen()
test_encryption(ee, cc)
"""
