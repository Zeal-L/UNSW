from ctypes import *


def encrypt(v, k):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9e3779b9 
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]

    total = c_uint32(0)
    for i in range(32):
        total.value += delta 
        v0.value += ((v1.value<<4) + k0) ^ (v1.value + total.value) ^ ((v1.value>>5) + k1)  
        v1.value += ((v0.value<<4) + k2) ^ (v0.value + total.value) ^ ((v0.value>>5) + k3)

    return v0.value, v1.value 


def decrypt(v, k):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9e3779b9 
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]

    total = c_uint32(delta * 32)
    for i in range(32):                       
        v1.value -= ((v0.value<<4) + k2) ^ (v0.value + total.value) ^ ((v0.value>>5) + k3) 
        v0.value -= ((v1.value<<4) + k0) ^ (v1.value + total.value) ^ ((v1.value>>5) + k1)  
        total.value -= delta

    return v0.value, v1.value  

# 9ccf1bec58a88b17feb81865e977c223
# 7c21fb101a6dd8f31748860044ee1b6d1500e2054a8a8a68e3fe5e2d66a10f6d7f4342b6d8caefbe0fe878dd571ee07c

# 9ccf1bec 58a88b17 feb81865 e977c223
# ec1bcf9c 178ba858 6518b8fe 23c277e9

# 7c21fb10 1a6dd8f3 17488600 44ee1b6d 1500e205 4a8a8a68 e3fe5e2d 66a10f6d 7f4342b6 d8caefbe 0fe878dd 571ee07c
# 10fb217c f3d86d1a 00864817 6d1bee44 05e20015 688a8a4a 2d5efee3 6d0fa166 b642437f beefcad8 dd78e80f 7ce01e57
# 504d4f43 31343836 6c65577b 656d6f63 206f7420 20746579 746f6e61 20726568 6b656577 20666f20 31343836 7d212121
# 434f4d50 36383431 7b57656c 636f6d65 20746f20 79657420 616e6f74 68657220 7765656b 206f6620 36383431 2121217d

# COMP6841{Welcome to yet another week of 6841!!!}

if __name__ == "__main__":
    # key = [0x9ccf1bec, 0x58a88b17, 0xfeb81865, 0xe977c223]
    # ['0x7c21fb10', '0x1a6dd8f3', '0x17488600', '0x44ee1b6d', 
    # '0x1500e205', '0x4a8a8a68', '0xe3fe5e2d', '0x66a10f6d', 
    # '0x7f4342b6', '0xd8caefbe', '0x0fe878dd', '0x571ee07c']
    # value = [0x7c21fb10, 0x1a6dd8f3]
    # res = decrypt(value, key)
    # print("Decrypted data is : ", hex(res[0]), hex(res[1]))

    # value = [0x17488600, 0x44ee1b6d]
    # res = decrypt(value, key)
    # print("Decrypted data is : ", hex(res[0]), hex(res[1]))

    # value = [0x1500e205, 0x4a8a8a68]
    # res = decrypt(value, key)
    # print("Decrypted data is : ", hex(res[0]), hex(res[1]))

    # value = [0xe3fe5e2d, 0x66a10f6d]
    # res = decrypt(value, key)
    # print("Decrypted data is : ", hex(res[0]), hex(res[1]))

    # value = [0x7f4342b6, 0xd8caefbe]
    # res = decrypt(value, key)
    # print("Decrypted data is : ", hex(res[0]), hex(res[1]))

    # value = [0x0fe878dd, 0x571ee07c]
    # res = decrypt(value, key)
    # print("Decrypted data is : ", hex(res[0]), hex(res[1]))
    a = "PMOC1486leW{emoc ot  teytona rehkeew fo 1486}!!!"
    print(a[::-1])

"""
Data is :  0x12345678 0x78563412
Encrypted data is :  0x9a65a69a 0x67ed00f6
Decrypted data is :  0x12345678 0x78563412
"""