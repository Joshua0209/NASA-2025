import hashlib
from pwn import *
import pickle
from tqdm import trange

# Build lookup: hash_prefix -> input_string
lookup = {}
for i in trange(2**24):
    h = hashlib.md5(str(i).encode()).hexdigest()[0:8]
    lookup[h] = str(i)

# # Save it for reuse
# with open('md5_lookup.pkl', 'wb') as f:
#     pickle.dump(lookup, f)

# with open('md5_lookup.pkl', 'rb') as f:
#     lookup = pickle.load(f)

r = remote('140.112.187.51', '1234')

r.sendlineafter(b'Your choice: ', b'4')
x = 1

for i in range(10):
    r.recvuntil(b'== "')

    chal = r.recv(8).strip().decode()
    r.recvuntil(b'" : ')
    r.sendline(lookup[chal].encode())

r.recvuntil(b'thanks: ')
flag = r.recvline().strip().decode()
r.close()

print(flag)

# NASA_HW11{https://youtu.be/1GxwDuV5JMc}
