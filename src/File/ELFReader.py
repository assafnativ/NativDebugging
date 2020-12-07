#
#   ELFReader.py
#
#   ELFReader - Read memory from ELF, usually a crash dump.
#   https://github.com/assafnativ/NativDebugging
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2020  Assaf Nativ
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
from bisect import bisect_left
from elftools.elf.elffile import ELFFile

try:
    import distorm3
    IS_DISASSEMBLER_FOUND = True
except ImportError as e:
    IS_DISASSEMBLER_FOUND = False
from struct import pack, unpack

def loadElf(targetFileName, file_start_offset=0, loading_address=0, pointer_size=4, endianity='='):
    return FileReader(targetFileName, file_start_offset, loading_address, pointer_size, endianity)

class FileReader( MemReaderBase, GUIDisplayBase ):
    def __init__( self, targetFileName, file_start_offset=0, loading_address=0, pointer_size=4, endianity='='):
        self._rawFile = open(targetFileName, 'rb')
        self._file = ELFFile(self._rawFile)
        MemReaderBase.__init__(self)
        self._POINTER_SIZE = pointer_size
        self._DEFAULT_DATA_SIZE = 4
        self._ENDIANITY = endianity

        self._segments = [x for x in self._file.iter_segments() if x.header['p_filesz'] and x.header['p_type'] != 'PT_NOTE']
        self._segInfo = [(x.data(), x.header['p_vaddr'], x.header, x) for x in self._segments]
        self._segInfo.sort(key=lambda x:x[1])
        self._segData = [x[0] for x in self._segInfo]
        self._regions = [(
            x[2]['p_type'],
            x[2]['p_vaddr'],
            x[2]['p_vaddr'] + x[2]['p_filesz']) for x in self._segInfo]
        self._regionEnds = [x[2] - 1 for x in self._regions]

        for readerName, (dataSize, packer) in MemReaderInterface.READER_DESC.items():
            def readerCreator(dataSize, packer):
                def readerMethod(self, address):
                    return struct.unpack(self._ENDIANITY + packer, self.readMemory(address, dataSize))[0]
                return readerMethod
            bind_method(FileReader, 'read'  + readerName, readerCreator(dataSize, packer))

    def __del__( self ):
        self._rawFile.close()

    def _findSegmentIndexForAddr(self, addr):
        index = bisect_left(self._regionEnds, addr)
        if len(self._regions) <= index:
            return -1
        region = self._regions[index]
        if addr < region[1]:
            return -1
        return index

    def readAddr( self, addr ):
        if 4 == self._POINTER_SIZE:
            return unpack(self._ENDIANITY + 'L', self.readMemory(addr, 4))[0]
        elif 8 == self._POINTER_SIZE:
            return unpack(self._ENDIANITY + 'Q', self.readMemory(addr, 8))[0]
        else:
            raise Exception("Unknown pointer size")

    def readMemory( self, addr, length ):
        index = self._findSegmentIndexForAddr(addr)
        if -1 == index:
            raise ReadError(addr)
        data = self._segData[index]
        region = self._regions[index]
        segOffset = addr - region[1]
        return bytes(data[segOffset:segOffset+length])

    def isAddressValid( self, addr ):
        return -1 != self._findSegmentIndexForAddr(addr)

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
        return 0

