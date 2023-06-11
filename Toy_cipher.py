import math
pt = 0b1111111111101111 #pt값 임의배정
key = 0b0011011101010101 #key값 임의배정


def list_chunk(pXk):

    global L1 #선언
    global R1 #선언
    
    print("-----list chunk-----")

    L1 = (pXk & 0b1111111100000000) >> 8
    R1 = pXk & 0b0000000011111111

    print(L1,R1)

    return L1, R1

def F_box(R):

    #input R = 매 라운드의 R. R1과 R2가 예정.

    #R1 = 10111010 = 186

    #ROL2 = 11101010 = 234
    #ROL2 + R1 = 420
    #(ROL2 + R1) % 2^8 = 420 % 256 = 164

    #ROL4 = 10101011 = 171
    #ROL4 + [(ROL2 + R1) % 2^8] = 335
    #[ROL4 + [(ROL2 + R1) % 2^8]] % 2^8 = 235 % 256 = 335 = 0b1001111

    ROL2 = ROL(R,2)
    ROL2_nemo = (ROL2 + R) % (2**8)

    ROL4 = ROL(R,4)
    res = (ROL2_nemo + ROL4) % (2**8)

    return res

def ROL(inputValue, n):
    #rotate left shift function 
    #inputValue : shifr 할 8bit. R1, R2가 예정.
    #n = shift count

    shift = inputValue << n
    shift &= 0b11111111
    src = inputValue >> (8 - n)
    res = shift | src
    return res


#pt XOR key
pXk = 0 # 선언 및 초기화
pXk = pt^key


#L1 R1 나누기
list_chunk(pXk)
#L1 = 11001000 = 200
#R1 = 10111010 = 186

R1_F = F_box(R1) #F-BOX나온 R1의 값 = 1001111 = 335
R2 = L1 ^ R1_F #L1 XOR R1_F = 11001000 XOR 01001111 = 10000111 = 135
L2 = R1 #L2 = R1 = 10111010 = 186
print(bin(L2), bin(R2))

R3 = R2 #R2 = 10000111 = 135
L3 = L2 ^ F_box(R2) #L2 XOR R2_F = 10111010 XOR 00011101 = 10100111
print(bin(L3), bin(R3))

ciphertext = (L3 << 8) + R3 #L3+R3 = 1010011110000111
ciphertext = bin(ciphertext)

print(ciphertext)
