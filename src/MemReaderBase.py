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

from future.utils import bind_method
from .Utilities import *
from .RecursiveFind import *
from .DumpBase import *

if 'WindowsError' not in globals():
    class WindowsError(Exception):
        pass

class MemReaderBase( RecursiveFind, DumpBase ):
    """ Few basic functions for memory reader, still abstract """
    def __init__(self):
        for readerName, (dataSize, packer) in MemReaderInterface.READER_DESC.items():
            def readerCreator(dataSize, packer):
                def readerMethod(self, address):
                    return struct.unpack(self._ENDIANITY + packer, self.readMemory(address, dataSize))[0]
                return readerMethod
            bind_method(MemReaderBase, 'read' + readerName, readerCreator(dataSize, packer))

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

    def readAddr(self, address):
        if 4 == self._POINTER_SIZE:
            return self.readUInt32(address)
        else:
            return self.readUInt64(address)

    def readString( self, addr, maxSize=None, isUnicode=False ):
        result = ''
        bytesCounter = 0

        while True:
            if False == isUnicode:
                c = self.readUInt8(addr + bytesCounter)
                bytesCounter += 1
            else:
                c = self.readUInt16(addr + bytesCounter)
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

    def readNPrintUInt64( self, addr, length=0x100, isNoBase=True, itemsInRow=4, endianity=None ):
        """
        Display memory as UInt64 tabls, does not return anything
        """
        if None == endianity:
            endianity = self.getEndianity()
        if isNoBase:
            printAsUInt64Table(self.readMemory(addr, length), itemsInRow=itemsInRow, endianity=endianity)
        else:
            printAsUInt64Table(self.readMemory(addr, length), addr, itemsInRow=itemsInRow, endianity=endianity)

    def readNPrintUInt32( self, addr, length=0x100, isNoBase=True, itemsInRow=8, endianity=None ):
        """
        Display memory as UInt32 tabls, does not return anything
        """
        if None == endianity:
            endianity = self.getEndianity()
        if isNoBase:
            printAsUInt32Table(self.readMemory(addr, length), itemsInRow=itemsInRow, endianity=endianity)
        else:
            printAsUInt32Table(self.readMemory(addr, length), addr, itemsInRow=itemsInRow, endianity=endianity)

    def readNPrintUInt16( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10, endianity=None ):
        """
        Display memory as UInt16 tabls, does not return anything
        """
        if None == endianity:
            endianity = self.getEndianity()
        if isNoBase:
            printAsUInt16Table(self.readMemory(addr, length), itemsInRow=itemsInRow, endianity=endianity)
        else:
            printAsUInt16Table(self.readMemory(addr, length), addr, itemsInRow=itemsInRow, endianity=endianity)

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


