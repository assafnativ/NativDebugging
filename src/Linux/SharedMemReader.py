#
#   SharedMemReader.py
#
#   SharedMemReader - Attach and read shared memory on *nix platforms
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
from ctypes import *

from ..Interfaces import MemReaderInterface, GUIDisplayInterface
from ..Utile import *
try:
    from ..QtWidgets import *
    IS_GUI_FOUND = True
except ImportError, e:
    #print("No GUI support")
    IS_GUI_FOUND = False

def getIpcsInfo(isVerbos=True):
    p = Popen(['ipcs', '-m'],stdout=subprocess.PIPE)
    out,err = p.communicate()
    lines = out.split('\n')
    if isVerbos:
        for i in lines:
            print i
    return lines 

def getAllShmidsInfo(shmidIndex=1,keyIndex=0,shSizeIndex=4):
    memInfo = getIpcsInfo(False)
    res=[]
    # We don't know how many lines belong to the header, so we try to parse it until we fail
    for i in memInfo:
        sLine = i.split()
        try:
            shmid  = int(sLine[shmidIndex])
            key    = int(sLine[keyIndex],16)
            shSize = int(sLine[shSizeIndex])
            res.append([key,shmid,shSize])
        except ValueError: 
            pass
        except IndexError:
            pass
    #res[[key,shmid,shSize]]
    return res

def getShmids(shmidIndex=1,keyIndex=0,shSizeIndex=4):
    memInfo = getAllShmidInfo(shmidIndex,keyIndex,shSizeIndex)
    return map(lambda x:x[1], memInfo)

class SharedMemInfo(Object):
    def __init__(self, id, start, end=None, size=None, base=None):
        self.id = id
        self.start = start
        if None == end and None == size:
            raise Exception("Need either mem size or end address")
        elif None == end:
            self.end = start + size
            self.size = size
        else:
            self.size = end - start
            self.end = end
        if None == base:
            self.base = start
            self.delta = 0
        else:
            self.base = base
            self.delta = self.start - base

def attachTo(memInfo):
    return SharedMemReader(memInfo)

class SharedMemReader( MemReaderInterface, GUIDisplayInterface ):
    def __init__(self, memInfos):
        libc = cdll.LoadLibrary("libc.so.6")
        # Support more than one shmid on input
        if list != type(memInfos):
            memInfos = [memInfos]
        for memInfo in memInfos:
            if 3 != len(memInfo) or tuple != type(memInfo):
                raise Exception("Meminfo of type (shared mem id, base address, size in bytes) expected")
        self.memMap = []
        for memInfo in memInfos:
            mem = self.libc.shmat(memInfo[0], 0, 010000) # 010000 == SHM_RDONLY
            if -1 == mem:
                raise Exception("Attach to shared memory failed")
            self.memMap.append(SharedMemInfo(memInfo[0], mem, size=memInfo[2], base=memInfo[1]))
    def remoteAddressToLocalAddress(address):
        for mem in memMap:
            if address >= mem.start and mem < mem.end:
                return address + mem.delta
        raise Exception("Address not in any attached memory")

    def __del__(self):
        for mem in memMap:
            self.libx.shmdt(mem.start)

    def readMemory(self, address, length, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        val = (c_ubyte * length).from_address(address)
        val = ''.join(map(chr, val))
        return val
    
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
        return c_void_p.from_address(address).value
    def isAddressValid(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        for mem in self.memMap:
            if address >= mem.start and address < mem.end:
                return True
        return False
    def readString(self, address, isLocalAddress=False):
        if not isLocalAddress:
            address = self.remoteAddressToLocalAddress(address)
        result = ''
        while True:
            c = self.readByte(address)
            address += 1
            if 0x20 <= c and c < 0x80:
                result += chr(c)
            else:
                return result



