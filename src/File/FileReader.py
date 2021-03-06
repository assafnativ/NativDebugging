#
#   MemoryReader.py
#
#   MemoryReader - Remote process memory inspection python module
#   https://svn3.xp-dev.com/svn/nativDebugging/
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2011  Assaf Nativ
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
#

from builtins import bytes
from future.utils import bind_method
import io
from ..Interfaces import MemReaderInterface, MemWriterInterface, ReadError
from ..Utilities import integer_types
from ..MemReaderBase import *
from ..GUIDisplayBase import *

try:
    import distorm3
    IS_DISASSEMBLER_FOUND = True
except ImportError as e:
    IS_DISASSEMBLER_FOUND = False
from struct import pack, unpack

def loadFile(targetFileName, file_start_offset=0, loading_address=0, pointer_size=4, endianity='='):
    return FileReader(targetFileName, file_start_offset, loading_address, pointer_size, endianity)

class FileReader( MemReaderBase, MemWriterInterface, GUIDisplayBase ):
    def __init__( self, targetFileName, file_start_offset=0, loading_address=0, pointer_size=4, endianity='='):
        self._file = io.open(targetFileName, 'rb+')
        MemReaderBase.__init__(self)
        self._POINTER_SIZE = pointer_size
        self._DEFAULT_DATA_SIZE = 4
        self._ENDIANITY = endianity
        self._START = file_start_offset
        self._LOADING_ADDR = loading_address
        self._ADDR_DELTA = file_start_offset - loading_address
        # Find end of file
        self._file.seek(0, 2)
        self._file_size = self._file.tell()

        for readerName, (dataSize, packer) in MemReaderInterface.READER_DESC.items():
            def readerCreator(dataSize, packer):
                def readerMethod(self, address):
                    self._file.seek(address + self._ADDR_DELTA)
                    return struct.unpack(self._ENDIANITY + packer, bytes(self._file.read(dataSize)))[0]
                return readerMethod
            def writerCreator(dataSize, packer):
                def writerMethod(self, address, value):
                    self._file.seek(address + self._ADDR_DELTA)
                    if isinstance(value, integer_types):
                        data = pack(self._ENDIANITY + packer, value)
                    self._file.write(value)
                return writerMethod
            bind_method(FileReader, 'read'  + readerName, readerCreator(dataSize, packer))
            bind_method(FileReader, 'write' + readerName, writerCreator(dataSize, packer))

    def __del__( self ):
        self._file.close()

    def readAddr( self, addr ):
        self._file.seek(addr + self._ADDR_DELTA)
        if 4 == self._POINTER_SIZE:
            return unpack(self._ENDIANITY + 'L', bytes(self._file.read(4)))[0]
        elif 8 == self._POINTER_SIZE:
            return unpack(self._ENDIANITY + 'Q', bytes(self._file.read(8)))[0]
        else:
            raise Exception("Unknown pointer size")

    def readMemory( self, addr, length ):
        self._file.seek(addr + self._ADDR_DELTA)
        return bytes(self._file.read(length))

    def readString( self, addr, maxSize=None, isUnicode=False ):
        result = ''
        bytesCounter = 0
        self._file.seek(addr + self._ADDR_DELTA)

        while True:
            if False == isUnicode:
                char = self._file.read(1)
                if len(char) != 1:
                    break
                char = ord(char)
                bytesCounter += 1
            else:
                char = self._file.read(2)
                if len(char) != 2:
                    break
                char = unpack(self._ENDIANITY + 'H', char)
                bytesCounter += 2
            if 1 < char and char < 0x80:
                result += chr(char)
            else:
                return result
            if None != maxSize and bytesCounter > maxSize:
                return result

    def writeAddr( self, addr, data ):
        self._file.seek(addr + self._ADDR_DELTA)
        if isinstance(data, integer_types):
            if 4 == self._POINTER_SIZE:
                data = pack(self._ENDIANITY + 'L', data)
            elif 8 == self._POINTER_SIZE:
                data = pack(self._ENDIANITY + 'Q', data)
            else:
                raise Exception("Unknown pointer size")
        self._file.write(data)

    def writeMemory( self, addr, data ):
        self._file.self(addr + self._ADDR_DELTA)
        self._file.write(data)

    def isAddressValid( self, addr ):
        addr += self._ADDR_DELTA
        if addr > 0 and addr < self._file_size:
            return True
        return False

    def disasm(self, addr, length=0x100, decodeType=1):
        if IS_DISASSEMBLER_FOUND:
            for opcode in distorm3.Decode(
                    addr,
                    self.readMemory(addr, length),
                    decodeType):
                print('{0:x} {1:24s} {2:s}'.format(opcode[0], opcode[3], opcode[2]))
        else:
            raise Exception("No disassembler module")

    def getLoadingAddress(self):
        return self._LOADING_ADDR

    def getFileOffset(self):
        return self._START

