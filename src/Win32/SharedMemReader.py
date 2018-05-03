#
#   SharedMemReader.py
#
#   SharedMemReader - Attach and read shared memory on Windows platforms
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
import struct
from ctypes import c_char, c_void_p, c_int8, c_int16, c_int32, c_int64, c_uint8, c_uint16, c_uint32, c_uint64, cdll, sizeof
from .Win32Structs import *
from .Win32Utilities import *

from ..Interfaces import ReadError
from ..MemReaderBase import *
from ..GUIDisplayBase import *
from ..Utilities import *
try:
    from ..QtWidgets import *
    IS_GUI_FOUND = True
except ImportError as e:
    #print("No GUI support")
    IS_GUI_FOUND = False

class SharedMemInfo(object):
    def __init__(self, id, localAddress, base, size, mappingHandle):
        self.id = id
        self.localAddress = localAddress
        self.localAddressEnd = localAddress + size
        self.end = base + size
        self.size = size
        self.base = base
        self.delta = self.localAddress - base
        self.mappingHandle = mappingHandle
    def __repr__(self):
        return "MemInfo:Id0x%x:Base0x%x:End0x%x:LocalAddress0x%x" % (self.id, self.base, self.end, self.localAddress)

def attach(memInfo):
    """ memInfo: (memName, baseAddress, size) """
    return SharedMemReader(memInfo)

class SharedMemReader( MemReaderBase, GUIDisplayBase ):
    def __init__(self, memInfos):
        MemReaderBase.__init__(self)
        self._POINTER_SIZE = sizeof(c_void_p)
        self._DEFAULT_DATA_SIZE = 4
        self._ENDIANITY = '<'

        # Support more than one shmid on input
        if not isinstance(memInfos, list):
            memInfos = [memInfos]
        for memInfo in memInfos:
            if 3 != len(memInfo) or tuple != type(memInfo):
                raise Exception("Meminfo of type (shared mem id, base address, size in bytes) expected")
        self.memMap = []
        for memInfo in memInfos:
            mappingHandle = OpenFileMapping(
                                    win32con.FILE_MAP_READ,
                                    0,
                                    memInfo[0] )
            localAddress = MapViewOfFile(
                                mappingHandle,
                                win32con.FILE_MAP_READ,
                                0,
                                0,
                                memInfo[2])
            if None == localAddress:
                raise Exception("Map view of file failed for memory %s" %  memInfo[0])
            self.memMap.append(SharedMemInfo(
                                    memInfo[0],
                                    localAddress,
                                    memInfo[1],
                                    memInfo[2],
                                    mappingHandle))

    def remoteAddressToLocalAddress(self, address):
        for mem in self.memMap:
            if address >= mem.base and address < mem.end:
                return address + mem.delta
        raise ReadError(address)

    def __del__(self):
        self.__detach()

    def detach(self):
        self.__detach()
        del(self)

    def __detach(self):
        for mem in self.memMap:
            CloseHandle(mem.mappingHandle)
        self.memMap = []

    def getMemoryMap(self):
        memMap = {}
        for mem in self.memMap:
            memMap[mem.base] = ('%d' % mem.id, mem.size, 0xffffffff)
        return memMap

    def getPointerSize(self):
        return self._POINTER_SIZE

    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE

    def getEndianity(self):
        return self._ENDIANITY

    def readMemory(self, address, length, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        val = (c_char * length).from_address(address)
        return val.raw

    def readQword(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        return c_uint64.from_address(address).value
    def readDword(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        return c_uint32.from_address(address).value
    def readWord(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        return c_uint16.from_address(address).value
    def readByte(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        return c_uint8.from_address(address).value
    def readAddr(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        if 4 == self._POINTER_SIZE:
            return c_uint32.from_address(address).value
        else:
            return c_uint64.from_address(address).value

    def isAddressValid(self, address, isLocalAddress=False):
        if not isLocalAddress:
            for mem in self.memMap:
                if address >= mem.base and address < mem.end:
                    return True
        else:
            for mem in self.memMap:
                if address >= mem.localAddress and address < mem.localAddressEnd:
                    return True
        return False

    def readString( self, addr, isLocalAddress=False, maxSize=None, isUnicode=False ):
        result = ''
        bytesCounter = 0

        while True:
            if False == isUnicode:
                c = self.readByte(addr + bytesCounter, isLocalAddress=isLocalAddress)
                bytesCounter += 1
            else:
                c = self.readWord(addr + bytesCounter, isLocalAddress=isLocalAddress)
                bytesCounter += 2
            if 1 < c and c < 0x80:
                result += chr(c)
            else:
                return result
            if None != maxSize and bytesCounter > maxSize:
                return result

