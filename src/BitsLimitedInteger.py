class BitsLimitedInteger(object):
    def __init__(self, val, numBits=None):
        if isinstance(val, BitsLimitedInteger):
            self._numBits = val._numBits
            self._mask = val._mask
            self._val = val._val
        else:
            assert (0 < numBits) and (None != numBits), "Number of bits must be > 0"
            self._numBits = numBits
            self._mask = (1 << self._numBits) - 1
            self._val = val & self._mask
    def __add__(self, other):
        return BitsLimitedInteger(self._val + int(other._val), self._numBits)
    def __sub__(self, other):
        return BitsLimitedInteger(self._val - int(other._val), self._numBits)
    def __mul__(self, other):
        return BitsLimitedInteger(self._val * int(other._val), self._numBits)
    def __floordir__(self, other):
        return BitsLimitedInteger(self._val // int(other._val), self._numBits)
    def __mod__(self, other):
        return BitsLimitedInteger(self._val % int(other._val), self._numBits)
    def __pow__(self, other):
        return BitsLimitedInteger(self._val ** int(other._val), self._numBits)
    def __and__(self, other):
        return BitsLimitedInteger(self_val & int(other), self._numBits)
    def __or_(self, other):
        return BitsLimitedInteger(self_val | int(other), self._numBits)
    def __xor__(self, other):
        return BitsLimitedInteger(self_val ^ int(other), self._numBits)
    def __iand__(self, other):
        self._val &= int(other)
        self._val &= self._mask
        return self
    def __ior_(self, other):
        self._val |= int(other)
        self._val &= self._mask
        return self
    def __ixor__(self, other):
        self._val ^= int(other)
        self._val &= self._mask
        return self
    def __lt__(self, other):
        return self._val < int(other)
    def __gt__(self, other):
        return self._val > int(other)
    def __le__(self, other):
        return self._val <= int(other)
    def __ge__(self, other):
        return self._val >= int(other)
    def __eq__(self, other):
        return self._val == int(other)
    def __ne__(self, other):
        return self._val != int(other)
    def __isub__(self, other):
        self._val -= int(other)
        self._val &= self._mask
        return self
    def __iadd__(self, other):
        self._val += int(other)
        self._val &= self._mask
        return self
    def __imul__(self, other):
        self._val *= int(other)
        self._val &= self._mask
        return self
    def __ifloordiv__(self, other):
        self._val //= int(other)
        self._val &= self._mask
        return self
    def __ipow__(self, other):
        self._val **= int(other)
        self._val &= self._mask
        return self
    def __neg__(self):
        return BitsLimitedInteger(self._mask - self._val + 1, self._numBits)
    def __invert__(self):
        return BitsLimitedInteger(self._mask - self._val, self._numBits)
    def __not__(self):
        return not self._val
    def __int__(self):
        return self._val
    def __hex__(self):
        return hex(self._val)
    def __repr__(self):
        return "0x%x|%x" % (self._val, self._mask)

