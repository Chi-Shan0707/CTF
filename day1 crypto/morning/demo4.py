import os
from hashlib import sha256
k=0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
a,b,c,d,e,f,g,h=0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
H=[a,b,c,d,e,f,g,h]
M=1<<32
def sha256_rotl(a,b):return (a>>(32-b)|a<<b)%M
def sha256_sr(a,b):return a>>b
def sha256_ch(x,y,z):return (x&y)^(~x&z)
def sha256_maj(x,y,z):return (x&y)^(x&z)^(y&z)
def sha256_e0(x):return sha256_rotl(x,30)^sha256_rotl(x,19)^sha256_rotl(x,10)
def sha256_e1(x):return sha256_rotl(x,26)^sha256_rotl(x,21)^sha256_rotl(x,7)
def sha256_o0(x):return sha256_rotl(x,25)^sha256_rotl(x,14)^sha256_sr(x,3)
def sha256_o1(x):return sha256_rotl(x,15)^sha256_rotl(x,13)^sha256_sr(x,10)
data=os.urandom(32)
ans=sha256(data).digest().hex()
w=[]
for i in range(8):
    w.append(0)
    for j in range(i*4,i*4+4):
        w[i]=w[i]*256+data[j]
w.append(2**31)
for i in range(9,15):
    w.append(0)
w.append(256)
for i in range(16,64):
    w.append((sha256_o1(w[i-2])+w[i-7]+sha256_o0(w[i-15])+w[i-16])%M)
for i in range(64):
    t1=(h+sha256_e1(e)+sha256_ch(e,f,g)+k[i]+w[i])%M
    t2=(sha256_e0(a)+sha256_maj(a,b,c))%M
    h=g
    g=f
    f=e
    e=(d+t1)%M
    d=c
    c=b
    b=a
    a=(t1+t2)%M
H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]=(H[0]+a)%M,(H[1]+b)%M,(H[2]+c)%M,(H[3]+d)%M,(H[4]+e)%M,(H[5]+f)%M,(H[6]+g)%M,(H[7]+h)%M
res=""
for i in range(8):
    res+=hex(H[i])[2:].zfill(8)
assert res==ans
print("data hex:", data.hex())
print("SHA256 OK - digest:", res)
