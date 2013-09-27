
from ..Interfaces import ReadError
from ..MemReaderBase import *
from ..GUIDisplayBase import *
from ..Utile import *
from struct import unpack

try:
    import distorm3
    IS_DISASSEMBLER_FOUND = True
except ImportError as e:
    IS_DISASSEMBLER_FOUND = False

def loadDump(dumpFile):
    return DumpReader(dumpFile)

class DumpReader( MemReaderBase, GUIDisplayBase ):
    def __init__(self, dumpFile, isVerbose=False):
        MemReaderBase.__init__(self)
        if isinstance(dumpFile, file):
            self.dumpFile = dumpFile
        else:
            self.dumpFile = file(dumpFile, 'rb')
        self._MEM_MAP = {}
        self._REGIONS = []
        self._DATA = {}
        self._COMMENTS = ""
        if 'NDMD' != self.dumpFile.read(4):
            raise Exception("This is not a NativDebugging dump file. Use FileReader to work with a raw dump")
        # Skip the size
        zero = self._dumpReadQword()
        if 0 != zero:
            raise Exception("Header parsing error")
        tag = self.dumpFile.read(4)
        while '' != tag:
            atomSize = self._dumpReadQword()
            if isVerbose:
                print("New ATOM %s of size 0x%x at %d" % (tag, atomSize, self.dumpFile.tell()))
            if 'INFO' == tag:
                if atomSize != 9:
                    raise Exception("Parse error at %d" % self.dumpFile.tell())
                self._POINTER_SIZE = self._dumpReadDword()
                self._DEFAULT_SIZE = self._dumpReadDword()
                self._ENDIANITY = self.dumpFile.read(1)
            elif 'REGN' == tag:
                addr = self._dumpReadQword()
                regionSize = self._dumpReadQword()
                regionAttributes = self._dumpReadDword()
                if 'NAME' != self.dumpFile.read(4):
                    raise Exception("Parse error at %d" % self.dumpFile.tell())
                nameLength = self._dumpReadQword()
                if 0 == nameLength:
                    regionName = ''
                else:
                    regionName = self.dumpFile.read(nameLength)
                self._MEM_MAP[addr] = (regionName, regionSize, regionAttributes)
            elif 'DATA' == tag:
                self._DATA[addr] = self.dumpFile.read(atomSize)
                self._REGIONS.append((addr, addr + atomSize))
                addr = None
                regionSize = None
                regionAttributes = None
            elif 'CMNT' == tag:
                self._COMMENTS = self.dumpFile.read(atomSize)

            tag = self.dumpFile.read(4)
        self.dumpFile.close()

    def _dumpReadDword(self):
        return unpack('>L', self.dumpFile.read(4))[0]
    def _dumpReadQword(self):
        return unpack('>Q', self.dumpFile.read(8))[0]

    def getComments(self):
        return self._COMMENTS

    def getMemoryMap(self):
        return self._MEM_MAP.copy()

    def searchBin(self, target):
        addresses = self._DATA.keys()
        addresses.sort()
        for base in addresses:
            pos = -1
            while True:
                pos = self._DATA[base].find(target, pos+1)
                if -1 != pos:
                    yield base + pos
                else:
                    break
    def disasm(self, addr, length=0x100, decodeType=1):
        if IS_DISASSEMBLER_FOUND:
            for opcode in distorm3.Decode(
                    addr, 
                    self.readMemory(addr, length),
                    decodeType):
                print('{0:x} {1:24s} {2:s}'.format(opcode[0], opcode[3], opcode[2]))
        else:
            raise Exception("No disassembler module")

    def isAddressValid(self, addr):
        for start, end in self._REGIONS:
            if start <= addr and addr > end:
                return True
        return False

    def getRegionStartEnd(self, addr):
        for r in self._REGIONS:
            if r[0] <= addr and addr < r[1]:
                return r
        return (0,0)

    def readMemory(self, addr, length):
        region = self.getRegionStartEnd(addr)
        if (addr + length) > region[1]:
            raise ReadError(region[1])
        offset = addr - region[0]
        return self._DATA[region[0]][offset:offset+length]

    def readQword(self, addr):
        return unpack(self._ENDIANITY + 'Q', self.readMemory(addr, 8))
    def readDword(self, addr):
        return unpack(self._ENDIANITY + 'L', self.readMemory(addr, 4))
    def readWord(self, addr):
        return unpack(self._ENDIANITY + 'H', self.readMemory(addr, 2))
    def readByte(self, addr):
        start, end = getRegionStartEnd(self, addr)
        return ord(self._DATA[start][addr - start])
    def readAddr(self, addr):
        if 4 == self._POINTER_SIZE:
            return self.readDword(addr)
        else:
            return self.readQword(addr)
    def readString( self, addr, maxSize=None, isUnicode=False ):
        result = ''
        bytesCounter = 0

        while True:
            if False == isUnicode:
                c = self.readByte(addr + bytesCounter)
                bytesCounter += 1
            else:
                c = self.readWord(addr + bytesCounter)
                bytesCounter += 2
            if 1 < c and c < 0x80:
                result += chr(c)
            else:
                return result
            if None != maxSize and bytesCounter > maxSize:
                return result

    def getPointerSize(self):
        return self._POINTER_SIZE
    def getDefaultDataSize(self):
        return self._DEFAULT_SIZE
    def getEndianity(self):
        return self._ENDIANITY



