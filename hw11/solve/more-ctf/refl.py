from pwn import *

p = remote('140.112.187.51', '1234')
v = remote('140.112.187.51', '1234')

v.sendlineafter(b'Your choice: ', b'5')
p.sendlineafter(b'Your choice: ', b'6')

v.recvuntil(b'nonce: ')
p.sendlineafter(b'nonce: ', v.recvline())
p.recvuntil(b'||')
proof = 'b10202012' + '||' + p.recvline().decode()
v.sendlineafter(b'shared_key)": ', proof.encode())
v.recvuntil(b'flag: ')
flag = v.recvline().decode().strip()

v.close()
p.close()
print(flag)

# NASA_HW11{y0u_KN0w_r3F13C710n_4774cK}
