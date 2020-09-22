之前在 cryptohack 上写题目遇到的一道题目,涉及 ECB Byte at Time ,这是个 baby 级的技术, 写这个只是想水一篇博文

因为 cryptohack 有声明不能随便在公网上发题解, 我就自己模仿了一道

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long
import os

KEY = os.urandom(16)
FLAG = b"flag{cracked_AES_mode_ECB}"

def encrypt(plaintext):
    padded = pad(plaintext + FLAG, 16)
    aes_cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        ciphertext = aes_cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}
    return {"ciphertext": hex(bytes_to_long(ciphertext))}


if __name__ == "__main__":
    while(1):
        ipt = input("get me plaintext: ").replace("\n", "")
        print(encrypt(ipt.encode()))
```

每一次加密的 KEY 都不变，加密的时候明文块大概是这样的(在这里个加密块大小为 128 位,也就是 16 字节)

```
+------------------+-----------------------------------------+
|    plaintext     |          FLAG   +   padding             |
+------------------+-----------------------------------------+
```

假设 plaintext 的长度跟加密块的长度一样,让 plaintext 的长度 -1

变成:

```
+-----------------------------+-----------------------------------------+
|  plaintext[:-1] + FLAG[0]   |          FLAG[1:]   +   padding         |
+-----------------------------+-----------------------------------------+
```

这时加密

FLAG 的一个字节会放在第一个块的末尾, 因为 plaintext 是我们的输入我们知道是啥, 但是我们不知道最后一位是什么,这时我们可以爆破, 我们一直构造第一个块的内容 plaintext[:-1] + [a-z]或者[1-9], [A-Z] ,然后再对构造的块进行加密只要得到的密文是和 plaintext[:-1] 加密的密文是一样的就说明 FLAG[0] 就是它

```bash
$ python3 ecb.py
get me plaintext: AAAAAAAAAAAAAAA
{'ciphertext': '0xb02177b29a20ecafa81fd200a75a8602463dc67bbdf13d3381ca88032722bc3432852a5732a03d96f8d3304e11b19854'}
get me plaintext: AAAAAAAAAAAAAAAf
{'ciphertext': '0xb02177b29a20ecafa81fd200a75a86021d7f6e048bcfd0a8096edc1c3e92fd9ff1839cc000a2850e6b176ef2955ae65a'}
```

可以看到我加密 `AAAAAAAAAAAAAAA` 和加密 `AAAAAAAAAAAAAAAf` 得到的密文是一样的, 可以看到第一个块明文得到的密文都是 `b02177b29a20ecafa81fd200a75a8602`

依次类推现在我输入 AAAAAAAAAAAAAA 和 AAAAAAAAAAAAAAfl 得到的结果是一样的

但是, 这样只能 leak 出 FLAG 的前 16 个字节

这里的 flag 长度是 26

改怎么做?

当然我们不会提前知道 flag 的长度,就需要我们自己去测试

```python
padded = pad(plaintext + FLAG, 16)
```

对明文加密前需要对齐 16 字节 Cryptdome 的 Pad 方式是 pad 的字符是`chr(16 - (len(plaintext)% 16))`

既然是这样我们就可以测出来 flag 到底是多少长, 因为一旦多出一个字节就会使得明文多出一个块, 密文也是一样

```bash
$ python3 ecb.py
get me plaintext:
{'ciphertext': '0x1d7f6e048bcfd0a8096edc1c3e92fd9ff1839cc000a2850e6b176ef2955ae65a'}
get me plaintext: A
{'ciphertext': '0x949817ef138474006bb308a9e662a7eef493c81f9e71011fdc683a29e8136c2'}
get me plaintext: AA
{'ciphertext': '0x86e1a263789cf51be1abde312de355556b1d70a9579b7c65e38ec671508d687f'}
get me plaintext: AAA
{'ciphertext': '0x1c57f1b3b5e5ebff64d3f4a84ed358df7937551e0b09bbe8f38130a0dd910483'}
get me plaintext: AAAA
{'ciphertext': '0xc8e8483775163e1e66d3694efc835a964fd10885a86af40f5a7d6debed88b91f'}
get me plaintext: AAAAA
{'ciphertext': '0x5912c97a6f0c3c85cf7069c9522632cb2c61ec6bf5658a49ef3e3839e463de7c'}
get me plaintext: AAAAAA
{'ciphertext': '0x8022b3f5730d2a1605a88691259f6bc2ebbd0e0d23ab5c91955931da30512c5cb528aea0db7185345a43142e500da5a7'}
```

什么都不输入时密文的长度是 32 字节, 说明密文的长度小于等于 32 大于等于 16

可以发现我们在输入 6 个 A 时密文长度发生了变化

就说明实际上 padding 的长度是 6

flag 的长度为: `32 - 6 = 26`

现在知道了 flag 的长度为 26, 我们需要开始构造 payload

leak flag 第一个字节的 payload 是: "A" * 31 + x (我懒得计算， 直接 padding 到两个块的大小 - 1，x 是任意可见字符)

步骤:

1. 获取 "A" * 31 的对应的密文
2. 获取 "A" * 31 + x 的密文
3. 对比  "A" * 31 和 "A" * 31 + x 的密文, 若一样 flag 第一个字节就是 x
4. flag += x

依次类推

第二个字节： "A" * 30 + flag + y;   密文一样 flag += y

第三个字节： "A" * 29 + flag+ z；  密文一样 flag += z

..........



使用 netcat 把脚本挂在任意端口上

```bash
ncat -vc "python3 ecb.py" -kl 4444
```

写 payload

```python
from pwn import *
import string

dictionary = string.ascii_letters + "{}_"
r = remote("127.0.0.1", 4444)
r.recv()

payload = "A" * 31
flag_len = 26

flag = ""
enc = {}

for i in range(flag_len):
    r.sendline(payload[:31 - i])
    rmsg = r.recv().decode().split("'")[3]
    enc[rmsg[:66]] = i

print(enc)

for _ in range(26):
    for i in dictionary:
        payload_t = payload[:31 - len(flag)] + flag + i
        r.sendline(payload_t)
        rmsg = r.recv().decode().split("'")[3]
        if(rmsg[:66] in enc):
            flag += i
            print("[+] " + flag)
            break
    continue
```

我现在贼困，昨晚通宵看书，payload 没啥编码质量可言（又不是不能跑），睡觉。。。

```bash
$ python3 s.py
[.] Opening connection to 127.0.0.1 on port 4444: Trying 127.0.0.1
Ncat: Connection from 127.0.0.1.
[+] Opening connection to 127.0.0.1 on port 4444: Done
{'0x4cc46e408643df98294c3a029b87a529e28ead847e5174b2f10408de75581d1b': 0, '0x4cc46e408643df98294c3a029b87a529e77f612771a72e186375695804e86e4b': 1, '0x4cc46e408643df98294c3a029b87a52912e4118061b66d5e94d70ae2ce784e19': 2, '0x4cc46e408643df98294c3a029b87a529cd749aaac684fd6491609e5e843e4579': 3, '0x4cc46e408643df98294c3a029b87a529cda6e90fcc48e4990530fbd9fc40012a': 4, '0x4cc46e408643df98294c3a029b87a52972c2b8fc24ffe34e14a1b6dc8a89549d': 5, '0x4cc46e408643df98294c3a029b87a529388fa7a21ce25f3d794e09f8ddcad45e': 6, '0x4cc46e408643df98294c3a029b87a529fe6311195ba985f312068395a1f62007': 7, '0x4cc46e408643df98294c3a029b87a5292919ce6419b4abe58b0f4fc77734c140': 8, '0x4cc46e408643df98294c3a029b87a5298ecb7c4951685e0b3dccbe8e71c9e271': 9, '0x4cc46e408643df98294c3a029b87a529b47a3f4e8aee1344e12f750d29c75043': 10, '0x4cc46e408643df98294c3a029b87a529f7021ab32f9741a071b7e6417246905c': 11, '0x4cc46e408643df98294c3a029b87a529cbbdcccadf2f314f503074e29ccab6ca': 12, '0x4cc46e408643df98294c3a029b87a529d2b44b726ab280f22f0c0cf6489800ed': 13, '0x4cc46e408643df98294c3a029b87a529a98f93e2454a22d4db76941869a24e26': 14, '0x4cc46e408643df98294c3a029b87a5297f332d05f521ad2ea18a9601d4278476': 15, '0xe28ead847e5174b2f10408de75581d1bff4c98ed808d0ffc5074275c691e9a84': 16, '0xe77f612771a72e186375695804e86e4bdf4d25f279e8c9b4cf58b94871e289c2': 17, '0x12e4118061b66d5e94d70ae2ce784e19c0a9dae9978c5cfe96820cac56af86c6': 18, '0xcd749aaac684fd6491609e5e843e4579dc5ac2bae75ea045f84e99488bad71e1': 19, '0xcda6e90fcc48e4990530fbd9fc40012aac2e0c742b37884dd0e3343238ee3475': 20, '0x72c2b8fc24ffe34e14a1b6dc8a89549d44e17809ee1edff1a3f71cf67602e8d9': 21, '0x388fa7a21ce25f3d794e09f8ddcad45e102296eab403ced8c4bd46586c26b3a0': 22, '0xfe6311195ba985f312068395a1f62007e8ead991da1cb947048878c28ea686d4': 23, '0x2919ce6419b4abe58b0f4fc77734c140bea486e51039708ae1c53ffc1f8d7adb': 24, '0x8ecb7c4951685e0b3dccbe8e71c9e271c78e0c81f59b9ca5b6d315fe8bc206cc': 25}
[+] f
[+] fl
[+] fla
[+] flag
[+] flag{
[+] flag{c
[+] flag{cr
[+] flag{cra
[+] flag{crac
[+] flag{crack
[+] flag{cracke
[+] flag{cracked
[+] flag{cracked_
[+] flag{cracked_A
[+] flag{cracked_AE
[+] flag{cracked_AES
[+] flag{cracked_AES_
[+] flag{cracked_AES_m
[+] flag{cracked_AES_mo
[+] flag{cracked_AES_mod
[+] flag{cracked_AES_mode
[+] flag{cracked_AES_mode_
[+] flag{cracked_AES_mode_E
[+] flag{cracked_AES_mode_EC
[+] flag{cracked_AES_mode_ECB
[+] flag{cracked_AES_mode_ECB}
```

