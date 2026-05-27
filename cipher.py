import os


class LFSR:

    def __init__(self, poly, state):
     
        self.degree = poly[0]
        self.poly = poly
        self.feedback_taps = poly[1:] 
        self.mask = (1 << self.degree) - 1
        self.state = state & self.mask
        if self.state == 0:
            self.state = 1

    def output(self):
        return self.state & 1

    def clock(self):
        feedback = 0
        for tap in self.feedback_taps:
            feedback ^= (self.state >> tap) & 1
        self.state = ((self.state >> 1) | (feedback << (self.degree - 1))) & self.mask
        return self.output()

    def run(self, n):
        return [self.output() or self.clock() or self.output() for _ in range(n)]
    
    def generate_bits(self, n):
        bits = []
        for _ in range(n):
            bits.append(self.output())
            self.clock()
        return bits


class SPECTRALCipher:
   
    LFSR1_POLY = [19, 18, 17, 14, 0]
    LFSR2_POLY = [23, 22, 21, 16, 0]
    LFSR3_POLY = [29, 28, 25, 2, 0]

    def __init__(self, key=None):
        if key is None:
            key = int.from_bytes(os.urandom(9), 'big')
            key &= (1 << 71) - 1

        if key <= 0 or key >= (1 << 71):
            raise ValueError("Key must be a positive 71-bit integer")

        self.key = key

        state1 = (key >> 52) & ((1 << 19) - 1)
        state2 = (key >> 29) & ((1 << 23) - 1)
        state3 = key & ((1 << 29) - 1)

        if state1 == 0:
            state1 = 1
        if state2 == 0:
            state2 = 1
        if state3 == 0:
            state3 = 1

        self.lfsr1 = LFSR(self.LFSR1_POLY, state1)
        self.lfsr2 = LFSR(self.LFSR2_POLY, state2)
        self.lfsr3 = LFSR(self.LFSR3_POLY, state3)

    @staticmethod
    def combining_function(x1, x2, x3):
        return x1 ^ (x2 & x3)

    def keystream_bit(self):
        x1 = self.lfsr1.output()
        x2 = self.lfsr2.output()
        x3 = self.lfsr3.output()
        z = self.combining_function(x1, x2, x3)
        self.lfsr1.clock()
        self.lfsr2.clock()
        self.lfsr3.clock()
        return z

    def keystream_bytes(self, n):
        result = bytearray()
        for _ in range(n):
            byte = 0
            for j in range(8):
                byte |= (self.keystream_bit() << j)
            result.append(byte)
        return bytes(result)

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        ks = self.keystream_bytes(len(plaintext))
        return bytes(a ^ b for a, b in zip(plaintext, ks))

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
