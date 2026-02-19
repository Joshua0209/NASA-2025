from pwn import *
from binascii import unhexlify, hexlify

r = remote('140.112.187.51', '1234')
# r = remote('localhost', '12345')
r.sendlineafter(b'Your choice: ', b'3')

r.recvuntil(b'pad!!!\n')

cip = unhexlify(r.recvline().strip().decode())

r.close()


prefix = b"NASA_HW11{"

key_len = 10
for off in range(len(cip)-key_len):
    key = bytes(cip[i+off] ^ prefix[i] for i in range(key_len))
    mes = bytes(cip[i+off] ^ key[i % key_len] for i in range(len(cip)-off))
    try:
        mes = mes.decode()
        if mes.isprintable() and '}' in mes:
            print(mes)
    except:
        pass

# NASA_HW11{07p_k3y_mu57_b3_47_l3457_45_l0n6_45_pl41n73x7}
