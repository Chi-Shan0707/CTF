from random import choice
from Crypto.Util.number import bytes_to_long, long_to_bytes

with open('flag.txt', 'r') as file:
    flag = file.read()

# 说明（高层）:
#  - 这个文件实现了一个简化的类 DES 的加密流程（Feistel 结构、S 盒、扩展 E、置换 P 等），
#    但只实现了加密函数 `encrypt`，没有实现解密函数 `decrypt`。
#  - Feistel 结构本身是可逆的：只要知道所有子密钥并按轮序逆序执行逆向变换，就能恢复明文。
#  - 然而这个实现存在使得“实际不可逆”的原因（即使数学上可逆）：
#    1) 填充使用的是尾部补零（`padded_flag = bin_flag + '0'*padded_len`），但**未保存原始明文长度**或使用可区分的填充格式；
#       因此无法区分原始末尾本来就是 0 的位与用于填充的 0 —— 恢复后的明文结尾可能包含额外的零字节，导致信息丢失或模糊。
#    2) 类实例在初始化时随机生成了 `self.key`（并在内存中生成 `self.subkey`），**没有把密钥持久化或导出**；若密钥丢失，则无法解密。
#    3) 文件中未提供解密接口，调用方无法利用现有代码完成逆变换（即便拥有密钥也需要实现解密步骤）。
#  - 另外，轮数非常少（这里只循环 2 次）会导致安全性不足，但并不直接导致数学不可逆性。


class MACHINE:
    def __init__(self):
        self.alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!?()\n'

        self.IP = [58, 50, 42, 34, 26, 18, 10, 2,
              60, 52, 44, 36, 28, 20, 12, 4,
              62, 54, 46, 38, 30, 22, 14, 6,
              64, 56, 48, 40, 32, 24, 16, 8,
              57, 49, 41, 33, 25, 17, 9, 1,
              59, 51, 43, 35, 27, 19, 11, 3,
              61, 53, 45, 37, 29, 21, 13, 5,
              63, 55, 47, 39, 31, 23, 15, 7
              ]

        self.IP_inv = [self.IP.index(i) + 1 for i in range(1, 65)]

        self.S1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
              0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
              4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
              15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
              ]
        self.S2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
              3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
              0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
              13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
              ]
        self.S3 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
              13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
              13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
              1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
              ]
        self.S4 = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
              13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
              10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
              3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
              ]
        self.S5 = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
              14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
              4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
              11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
              ]
        self.S6 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
              10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
              9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
              4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
              ]
        self.S7 = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
              13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
              1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
              6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
              ]
        self.S8 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
              1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
              7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
              2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
              ]
        self.S = [self.S1, self.S2, self.S3, self.S4, self.S5, self.S6, self.S7, self.S8]

        self.E = [32, 1, 2, 3, 4, 5, 4, 5,
             6, 7, 8, 9, 8, 9, 10, 11,
             12, 13, 12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21, 20, 21,
             22, 23, 24, 25, 24, 25, 26, 27,
             28, 29, 28, 29, 30, 31, 32, 1
             ]

        self.P = [16, 7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26, 5, 18, 31, 10,
             2, 8, 24, 14, 32, 27, 3, 9,
             19, 13, 30, 6, 22, 11, 4, 25
             ]

        self.PC_1 = [57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
                ]

        self.PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56,
                34, 53, 46, 42, 50, 36, 29, 32
                ]

        self.shift_num = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        self.key = ''.join(choice(self.alphabet) for _ in range(8))
        self.subkey = self.generate_key(self.key.encode())

    def generate_key(self, ori_key):
        key = bin(bytes_to_long(ori_key))[2:].zfill(64)
        subkeys = []
        temp = [key[i - 1] for i in self.PC_1]
        for i in self.shift_num:
            temp[:28] = temp[:28][i:] + temp[:28][:i]
            temp[28:] = temp[28:][i:] + temp[28:][:i]
            subkeys.append(''.join(temp[j - 1] for j in self.PC_2))
        return subkeys

    def encrypt(self, text):
        if isinstance(text, str):
            text = text.encode()
        # 把字节串变为位字符串（每字节 8 位）
        bin_flag = ''.join([bin(byte)[2:].zfill(8) for byte in text])

        # 这里使用简单的 "尾部补 0" 填充：
        #  - 优点：实现简单；缺点：如果不记录原始长度或没有采用可区分的填充规则，
        #    解密时无法判断哪些 0 是填充而哪些是原始数据，从而导致不可逆（信息丢失）。
        padded_len = (64 - (len(bin_flag) % 64)) % 64
        padded_flag = bin_flag + '0' * padded_len

        # 按 64-bit 分块
        cate_text = [padded_flag[i * 64:(i + 1) * 64] for i in range(0, len(padded_flag) // 64)]

        encrypted_text = ''
        for text in cate_text:
            t = ''.join(text[i - 1] for i in self.IP)
            L, R = t[:32], t[32:]

            # 轮函数（简化 DES 流程）：这里只进行了 2 轮 Feistel 变换
            # 注意：Feistel 结构本身可逆，但本文件没有实现对应的逆向解密函数。
            for cnt in range(2):
                R_temp = R
                k = self.subkey[cnt]
                R_expanded = ''.join(R[i - 1] for i in self.E)
                R_xor = [str(int(R_expanded[i]) ^ int(k[i])) for i in range(48)]
                R_groups = [R_xor[i:i + 6] for i in range(0, 48, 6)]
                res = ''
                for i in range(8):
                    row = int(R_groups[i][0] + R_groups[i][5], base=2)
                    col = int(''.join(R_groups[i][1:5]), base=2)
                    int_res = self.S[i][16 * row + col]
                    res += bin(int_res)[2:].zfill(4)

                res_p = ''.join(res[i - 1] for i in self.P)
                new_R = ''.join(str(int(res_p[i]) ^ int(L[i])) for i in range(32))
                R = new_R
                L = R_temp

            t = R + L
            t = ''.join(t[i - 1] for i in self.IP_inv)
            encrypted_text += t

        # 把位串重新组装成字节串返回
        # 注意：此处没有记录原始明文长度，解密时无法恢复确切的末尾字节数（除非采用明确填充协议）。
        encrypted_bytes = b''
        for i in range(0, len(encrypted_text), 8):
            byte = int(encrypted_text[i:i + 8], 2)
            encrypted_bytes += bytes([byte])
        encrypted_text = encrypted_bytes
        return encrypted_text

machine = MACHINE()
text = ''.join(choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!?()\n') for _ in range(80))
en_text = machine.encrypt(text)
en_flag = machine.encrypt(flag)

print("Encrypted flag:", bytes_to_long(en_flag))
print("Random text:", bytes_to_long(text.encode()))
print("Encrypted random text:", bytes_to_long(en_text))

# Random text: 1733571697283962509488226713108269753699322498714010326656310076489877844089729148788129403124099930593602491145395337324365415309638864335256126266980930992016878248102013062728229825856295255
# Encrypted random text: 3578059052586522474100389050030320588160089073371878413925896715373042626307922378489203525965322427489129100605094275877241918595390796602423805072859665451626477779012814084741966341775758398