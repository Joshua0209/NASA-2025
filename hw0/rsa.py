import base64
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA
with open("private.pem", "rb") as f:
    data = f.read()
    mykey = RSA.import_key(data)
print(hex(mykey.n)[-8:])

# cipher = r"TGrWiRVLkgERlb11jN3lhwhBrCSwR5gbS/YMs0WzinxXrV9AG4ieZwf/NpEn3wEn57h+gmL5ckJmdhxryGzX8A=="
# N = 11886078828575428410020184764338155811658327177871252212581222928669891297689718738754964192534523861584253899371187963332753196380561253587057164370681391
# d = 3251501003077655073238657131926308152515533052243401584862843350553028231151523084809142358650966102613814652594272729839958098853130285914704018410410881


# cipher_bytes = base64.b64decode(cipher)
# c = bytes_to_long(cipher_bytes)

# n = pow(c, d, N)
# m = long_to_bytes(n)
# print(m)
