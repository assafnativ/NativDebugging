#
#   MemReaderBase.py
#
#   MemReaderBase - Implements the common methods of all memory readers
#   https://github.com/assafnativ/NativDebugging.git
#   Nativ.Assaf@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

from abc import ABCMeta
from .Interfaces import MemReaderInterface, ReadError
from .Utile import *
from .RecursiveFind import *
from .DumpBase import *

if 'WindowsError' not in globals():
    class WindowsError(Exception):
        pass

class MemReaderBase( RecursiveFind, DumpBase ):
    """ Few basic functions for memory reader, still abstruct """
    __metaclass__ = ABCMeta

    def __init__(self):
        self.solveAddr      = None
        self.findInSymbols  = None
        self.findSymbol     = None

        self.dd = self.readNPrintDwords
        self.db = self.readNPrintBin
        self.dw = self.readNPrintWords
        self.dq = self.readNPrintQwords
        self.resolveOffsets = self.resolveOffsetsList
        self.rol = self.resolveOffsetsList

    def resolveOffsetsList( self, start, l, isVerbose=False, isLookingForCycles=True ):
        """
        A quick way jump from one pointer to another.
        Starting from start address, reading the pointer at (start + l[0]), and then reads the pointer at the last result + l[1] and so on.
        The verbose option would print all of the pointers including the starting address.
        The isLookingForCycles option would alert the user in case one pointer is read more than once during the offsets walk.
        """
        result = [start]
        readFail = False
        cycleFound = False
        try:
            for i in l:
                nextAddr = self.readAddr(result[-1]+i)
                if nextAddr in result:
                    cycleFound = True
                result.append(nextAddr)
        except WindowsError as e:
            readFail = True
            result.append(-1)
        except ReadError as e:
            readFail = True
            result.append(-1)
        if True == isVerbose:
            if None != self.solveAddr:
                outputString = '['
                for i in range(len(result)):
                    addr = result[i]
                    addrName = self.solveAddr(addr)
                    if None != addrName:
                        outputString += addrName
                    else:
                        outputString += hex(addr)
                    if i != (len(result) - 1):
                        outputString += ', '
                outputString += ']'
                print(outputString)
            else:
                print(', '.join([hex(x) for x in result]))
            if readFail:
                print("Could not resolve all offsets")
        if True == isLookingForCycles and True == cycleFound:
            print("Offsets path contains a cycle")
        return result

    def readQword(self, address):
        return struct.unpack(self._ENDIANITY + 'Q', self.readMemory(address, 8))[0]

    def readDword(self, address):
        return struct.unpack(self._ENDIANITY + 'L', self.readMemory(address, 4))[0]

    def readWord(self, address):
        return struct.unpack(self._ENDIANITY + 'H', self.readMemory(address, 2))[0]

    def readByte(self, address):
        return ord(self.readMemory(address, 1))

    def readAddr(self, address):
        if 4 == self._POINTER_SIZE:
            return self.readDword(address)
        else:
            return self.readQword(address)

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
        return self._DEFAULT_DATA_SIZE

    def getEndianity(self):
        return self._ENDIANITY

    def readNPrintQwords( self, addr, length=0x100, isNoBase=True, itemsInRow=4, endianity=None ):
        """
        Display memory as QWords tabls, does not return anything
        """
        if None == endianity:
            endianity = self.getEndianity()
        if isNoBase:
            printAsQwordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow, endianity=endianity)
        else:
            printAsQwordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow, endianity=endianity)

    def readNPrintDwords( self, addr, length=0x100, isNoBase=True, itemsInRow=8, endianity=None ):
        """
        Display memory as DWords tabls, does not return anything
        """
        if None == endianity:
            endianity = self.getEndianity()
        if isNoBase:
            printAsDwordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow, endianity=endianity)
        else:
            printAsDwordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow, endianity=endianity)

    def readNPrintWords( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10, endianity=None ):
        """
        Display memory as Words tabls, does not return anything
        """
        if None == endianity:
            endianity = self.getEndianity()
        if isNoBase:
            printAsWordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow, endianity=endianity)
        else:
            printAsWordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow, endianity=endianity)

    def readNPrintBin( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10 ):
        """
        Display memory as bytes tabls, does not return anything
        """
        if isNoBase:
            print(DATA(self.readMemory(addr, length), itemsInRow=itemsInRow))
        else:
            print(DATA(self.readMemory(addr, length), addr, itemsInRow=itemsInRow))

    def findModule(self, target_module):
        for module in self.moduleList:
            if target_module in module.moduleName:
                return module.baseOfImage

    def getModulePath(self, base):
        for module in self.moduleList:
            if base == module.baseOfImage:
                return module.moduleName


