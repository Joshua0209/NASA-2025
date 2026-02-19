import hashlib
from tqdm import trange
with open("password.txt", "r") as f:
    data = f.read()

passwords = data.splitlines()
target = "40c3d69c8a012e181bd63d215d61a1df44e8fe7c182da6d24f26b0fae5348010"

for i in trange(len(passwords)):
    password = passwords[i]
    if hashlib.sha256(password.encode("utf-8")).hexdigest() == target:
        print(password)
        break
        # mortis00
