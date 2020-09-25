import random
from construct import bytes2bits

class LFSR:
    def __init__(self, init, feedback):
        self.state = init
        self.feedback = feedback
    @classmethod
    def random(cls, size):
        init = [random.choice([0, 1]) for i in range(size)]
        feedback = [random.choice([0, 1]) for i in range(size)]
        return cls(init, feedback)
    def getbit(self):
        nextbit = reduce(lambda x, y: x ^ y, [i & j for i, j in zip(self.state, self.feedback)])
        self.state = self.state[1:] + [nextbit]
        return nextbit
    def getbyte(self):
        b = 0
        for i in range(8):
            b = (b << 1) + self.getbit()
        return bytes([b])

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

"""
FLAG = open('./flag', 'rb').read()
assert FLAG.startswith(b'CTF{')

lfsr = LFSR.random(16)
key = b''.join([lfsr.getbyte() for i in range(len(FLAG))])
print(f'enc = {xor(FLAG, key).hex()}')
"""

enc = bytes.fromhex('d0aa72cef8dab5baac') # flag start with 'CTF{'
stream = xor(enc[:4], b'CTF{') # part of key
print(stream)
print(bytes2bits(stream))
s = [GF(2)(i) for i in bytes2bits(stream)] # transfer to bit, and then transfer to GF to limit value range (0~1)
feedback = ([0]*16 + berlekamp_massey(s).list()[:-1])[-16:] # less than 

