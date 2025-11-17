import math
import random

def generate_e(phi_n):
    for i in range(2, phi_n):
        if math.gcd(i, phi_n) == 1:
            return i

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = x0
        x0 = x1 - q * x0
        x1 = t
    if x1 < 0:
        x1 += m0
    return x1

def generate_random_e(phi_n):
    e = random.randint(2, phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    return e

def encrypt(M, public_key):
    # C ≡ M^e mod n, 0 <= M < n
    M = int(M, 16)
    if not (M >= 0 and M < public_key["n"]):
        raise ValueError(f"Your message in integer form is {M}, which is not in the range [0, n: {public_key['n']})")
    C = pow(M, public_key["e"], public_key["n"])
    return C

def decrypt(C, private_key):
    # M ≡ C^d mod n
    M = pow(C, private_key["d"], private_key["n"])
    M = hex(M)[2:].upper().rjust(16, "0")
    return M