from pwn import *
from tqdm import trange


class SuperRandomNumberGenerator:
    def __init__(self, state, a, c):
        self.state = state
        self.a = a
        self.c = c
        self.m = 0xa34d80e56c2cd0d35209cb13e5665fc58176fac6b1fee26af23388deebee59da1a884cbba6111ea819f7a2059f0accd8b1e7e23dbe4d90896b2cd482c0b934d97e3bbdbfd26b968e9bfeb2f8df037cab44557d2cf6eb57385a191c3db536c62f781e598405bdd818ae98dfd7df48c4da55d9d5b49d75aa46c91a27a186b9bf77

    def get_random(self):
        self.state = (self.state * self.a + self.c) % self.m
        return self.state


def solve_lcg(s0, s1, s2, m=0xa34d80e56c2cd0d35209cb13e5665fc58176fac6b1fee26af23388deebee59da1a884cbba6111ea819f7a2059f0accd8b1e7e23dbe4d90896b2cd482c0b934d97e3bbdbfd26b968e9bfeb2f8df037cab44557d2cf6eb57385a191c3db536c62f781e598405bdd818ae98dfd7df48c4da55d9d5b49d75aa46c91a27a186b9bf77):
    # a = (s2 - s1) * inverse(s1 - s0) mod m
    diff1 = (s1 - s0) % m
    diff2 = (s2 - s1) % m

    a = (diff2 * pow(diff1, -1, m)) % m
    c = (s1 - a * s0) % m
    return a, c


ss = []

r = remote('140.112.187.51', '1234')

for i in range(3):
    r.sendlineafter(b'Your choice: ', b'1')

    r.sendlineafter(b'number: ', b'1')
    r.recvuntil(b'picked is ')
    ss.append(int(r.recvuntil(b',').decode()[:-1]))

a, c = solve_lcg(*ss)
rng = SuperRandomNumberGenerator(ss[-1], a, c)

for i in trange(100):
    r.sendlineafter(b'Your choice: ', b'1')
    r.sendlineafter(b'number: ', str(rng.get_random()).encode())

r.sendlineafter(b'Your choice: ', b'2')
r.recvuntil(b'you: ')
flag = r.recvline().strip().decode()

r.close()
print(flag)
# NASA_HW11{pseudorandomness_does_not_guarantee_unpredictability}
