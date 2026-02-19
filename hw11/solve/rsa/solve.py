from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *
import gmpy2


def CRT(n, c):
    N = 1
    x = 0
    for i in range(len(n)):
        N *= n[i]
    for i in range(len(n)):
        b = N // n[i]
        b_prime = gmpy2.invert(b, n[i])
        x += c[i] * b * b_prime
        x %= N
    return x


target = b'name=soyo'
num = bytes_to_long(target)  # 2036162226816795244911
factors = [3, 19, 1933, 2029, 9108012537839]  # by factordb
x = [3*19*1933*2029, 9108012537839]
m = [long_to_bytes(x1) for x1 in x]

soya = remote('140.112.187.51', '11452')

enc = []
for m1 in m:
    soya.sendlineafter(b'> ', b'2')
    soya.sendlineafter(b'sign:\n', m1)
    soya.recvuntil(b'signature: ')
    enc.append(int(soya.recvline().decode().strip()))

soya.sendlineafter(b'> ', b'3')
soya.close()

cip = enc[0]*enc[1]

cs, ns = [], []
for i in range(7):
    anon = remote('140.112.187.51', '11451')
    anon.sendlineafter(b'ID: ', target)
    anon.sendlineafter(b'Signature: ', str(cip).encode())
    anon.recvuntil(b'Soyorin: ')
    flag1 = anon.recvline().decode().strip()
    anon.sendlineafter(b'> ', b'1')
    anon.recvuntil(b'(e, n): (')
    e, n = anon.recvuntil(b')').decode()[:-1].split(',')
    ns.append(int(n))
    anon.sendlineafter(b'> ', b'2')
    anon.recvuntil(b'diary c: ')
    c = anon.recvline().decode()
    cs.append(int(c))
    anon.close()

print(cs)
print()
print(ns)
m_decrypt = gmpy2.iroot(CRT(ns, cs), e)[0]
flag2 = long_to_bytes(m_decrypt).decode()
print(flag1)
# NASA_HW11{blind_signing_is_dangerous}
print(flag2)
# Anon's Secret Diary: Today, I went to a Mister Donut nearby and met Sumita Mana from Sumimi! She assured me it's safe to use a small public exponent in RSA encryption because RSA is super secure. I trust her completely, as she wouldn't lie to me! By the way, my secret flag is:
# NASA_HW11{W0w_y0u_kNow_h@st@d'5_bro4dc@s7_47t@cK}
