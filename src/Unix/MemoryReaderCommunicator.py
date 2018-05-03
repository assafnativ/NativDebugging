#
#   memoryReaderCommunicator.py
#
#   memoryReaderCommunicator - A python wrapper for memory reader under *nix platforms
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

import sys
import os
import subprocess
import struct

from ..Interfaces import ReadError
from ..MemReaderBase import *
from ..Utilities import *

def attach(memInfo, pointerSize, defaultSize):
    """
    memInfo = (id, base, size)
    pointerSize = 4 or 8
    defaultSize = 4 or 8
    """
    return SharedMemReader(memInfo, pointerSize, defaultSize)

class SharedMemInfo(object):
    def __init__(self, id, base, size):
        self.id = id
        self.end = base + size
        self.size = size
        self.base = base
    def __repr__(self):
        return "MemInfo:Id0x%x:Base0x%x:End0x%x" % (self.id, self.base, self.end)

class SharedMemReader( MemReaderBase ):
    def __init__(self, memInfos, pointerSize, defaultSize):
        MemReaderBase.__init__(self)
        self._POINTER_SIZE = pointerSize
        self._DEFAULT_DATA_SIZE = defaultSize
        self._ENDIANITY = '='
        self._READER_NAME = \
            ['./memReader32', './memReader64'][self._POINTER_SIZE==8]
        # Support more than one shmid on input
        if not isinstance(memInfos, list):
            memInfos = [memInfos]
        for memInfo in memInfos:
            if 3 != len(memInfo) or tuple != type(memInfo):
                raise Exception("Meminfo of type (shared mem id, base address, size in bytes) expected")
        self.memMap = []
        for memInfo in memInfos:
            sharedMem = SharedMemInfo(memInfo[0], memInfo[1], memInfo[2])
            reader = subprocess.Popen(
                    [
                        self._READER_NAME,
                        '%d' % sharedMem.id,
                        '%x' % sharedMem.base,
                        '%x' % sharedMem.size ],
                    stdin  = subprocess.PIPE,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.STDOUT )
            sharedMem.reader = reader
            self.memMap.append(sharedMem)

    def __del__(self):
        self.__detach()

    def detach(self):
        del(self)

    def __detach(self):
        for mem in self.memMap:
            mem.reader.stdin.write('0 0' + os.linesep)
            mem.reader.communicate()

    def getMemoryMap(self):
        memMap = {}
        for mem in self.memMap:
            memMap[mem.base] = ('%d' % mem.id, mem.size, 0xffffffff)
        return memMap

    def __findReader(self, address):
        for mem in self.memMap:
            if address >= mem.base and address < mem.end:
                return mem.reader
        raise ReadError(address)

    def readMemory(self, address, length):
        reader = self.__findReader(address)
        reader.stdin.write('%x %x%s' % (address, length, os.linesep))
        value = reader.stdout.readline()
        if 'Invalid' in value:
            raise ReadError(address)
        value = value.strip()
        value = value.decode('hex')
        if len(value) != length:
            raise ReadError(address)
        return value

    def isAddressValid(self, address):
        for mem in self.memMap:
            if address >= mem.base and address < mem.end:
                return True
        return False
