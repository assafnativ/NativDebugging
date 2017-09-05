#
#   MemReaderInProcess.py
#
#   MemReaderInProcess - Read memory from the process the script is
#   running from. Usefull with thread injection, or Python embedded.
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

from __future__ import print_function
import ctypes
from ctypes import c_size_t, c_void_p, c_char, c_char_p, c_uint8, c_uint16, c_uint32, c_uint64, cdll, windll, byref
import os
import platform
from struct import pack, unpack
from Interfaces import MemWriterInterface, ReadError, WriteError
from MemReaderBase import *

class MemReaderInProcess( MemReaderBase ):
    def __init__(self, memcpy=None, memmap=None):
        MemReaderBase.__init__(self)
        self._POINTER_SIZE = ctypes.sizeof(c_void_p)
        self._DEFAULT_DATA_SIZE = 4
        self._PID = os.getpid()
        t = pack('=L', 1)
        if '\x00' == t[0]:
            self._ENDIANITY = '>'
        else:
            self._ENDIANITY = '<'
        if None == memcpy:
            if 'Windows' in platform.platform():
                self._memcpy = cdll.msvcrt.memcpy
            elif 'Linux' in platform.platform():
                for libc_ver in range(10, 3, -1):
                    try:
                        libc = cdll.LoadLibrary('libc.so.%d' % libc_ver)
                        break
                    except:
                        libc = None
                if None == libc:
                    raise Exception("Please provide a memcpy function")
                self._memcpy = libc.memcpy
            else:
                raise Exception("Please provide a memcpy function")
            self._memcpy.argtypes = [
                    c_void_p,
                    c_void_p,
                    c_size_t ]
            self._memcpy.restype = None
        else:
            self._memcpy = memcpy
        if None == memmap:
            if 'Windows' in platform.platform():
                self._memMap = self._winGetMemoryMap()
            elif 'Linux' in platform.platform():
                self._memMap = self._linuxGetMemoryMap()
            else:
                raise Exception("Please provide a memory map")
        else:
            self._memMap = memmap

    def _winGetMemoryMap(self):
        # Find the number of pages in the workingset
        QueryWorkingSet = windll.psapi.QueryWorkingSet
        QueryWorkingSet.argtypes = [
            c_void_p,   # HANDLE hProcess
            c_void_p,   # PVOID pv
            c_uint32]     # DWORD cb
        QueryWorkingSet.restype = c_uint32
        GetCurrentProcess = windll.kernel32.GetCurrentProcess
        GetCurrentProcess.argtypes = []
        GetCurrentProcess.restype = c_uint32
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [("BaseAddress", c_void_p),
                        ("AllocationBase", c_void_p),
                        ("AllocationProtect", c_uint32),
                        ("RegionSize", c_size_t),
                        ("State", c_uint32),
                        ("Protect", c_uint32),
                        ("Type", c_uint32)]
        GetSystemInfo = windll.kernel32.GetSystemInfo
        GetSystemInfo.argtypes = [ c_void_p ] # LPSYSTEM_INFO
        GetSystemInfo.restype = None
        class SYSTEM_INFO( ctypes.Structure ):
            _fields_ = [
                    ('wProcessorArchitecture', c_uint16),
                    ('wReserved',              c_uint16),
                    ('dwPageSize',             c_uint32),
                    ('lpMinimumApplicationAddress', c_void_p),
                    ('lpMaximumApplicationAddress', c_void_p),
                    ('dwActiveProcessorMask',       c_void_p),
                    ('dwNumberOfProcessors',        c_uint32),
                    ('dwProcessorType',             c_uint32),
                    ('dwAllocationGranularity',     c_uint32),
                    ('wProcessorLevel',             c_uint32),
                    ('wProcessorRevision',          c_uint32) ]
        sysInfo = SYSTEM_INFO()
        GetSystemInfo(byref(sysInfo))
        self._minVAddress   = sysInfo.lpMinimumApplicationAddress
        self._maxVAddress   = sysInfo.lpMaximumApplicationAddress
        self._pageSize      = sysInfo.dwPageSize
        self._pageSizeMask  = self._pageSize - 1
        self._pageMask = ~self._pageSizeMask
        num_pages = c_uint64(0)
        QueryWorkingSet(GetCurrentProcess(), byref(num_pages), ctypes.sizeof(c_uint64))

        # Get all other memory and attributes of pages
        memory_map = ctypes.ARRAY( c_void_p, (num_pages.value + 0x100) * ctypes.sizeof(c_void_p) )(0)
        QueryWorkingSet(GetCurrentProcess(), byref(memory_map), ctypes.sizeof(memory_map))
        number_of_pages = memory_map[0]
        memoryRegionInfo = MEMORY_BASIC_INFORMATION()
        pages = memory_map[1:number_of_pages]

        result = {}
        pageSize = self._pageSize
        pageMask = self._pageMask
        for page in pages:
            protection = page & 0x7
            if 0 != protection:
                addr = page & pageMask
                result[addr] = ('', pageSize, protection)

        return result

    def _linuxGetMemoryMap(self):
        import resource
        self._pageSize = resource.getpagesize()
        self._pageSizeMask = self._pageSize - 1
        memMapInfo = open('/proc/%d/maps' % self._PID, 'r').readlines()
        result = {}
        for line in memMapInfo:
            line = line.strip()
            if '' == line:
                break
            pos = line.find('-')
            start = int(line[:pos], 16)
            endPos = line.find(' ', pos)
            pos += 1
            end = int(line[pos:endPos])
            pos = endPos + 1
            protection = 0
            if 'r' == line[pos]:
                protection |= 1
                pos += 1
                if 'w' == line[pos]:
                    protection |= 4
                pos += 1
                if 'x' == line[pos]:
                    protection |= 2
                for addr in range(start, end, self._pageSize):
                    result[addr] = ('', addr, protection)
        return result

    def getPointerSize(self):
        return self._POINTER_SIZE

    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE

    def getEndianity(self):
        return self._ENDIANITY

    def getMemoryMap(self):
        return self._memMap.copy()

    def _readCtype(self, ctype, address, length):
        startPage   = address & self._pageMask
        endPage     = (address + length) & self._pageMask
        if not self._memMap.has_key(startPage):
            return True
        if endPage != startPage and not self._memMap.has_key(endPage):
            return True
        self._memcpy(byref(ctype), address, length)
        return False

    def readMemory(self, address, length):
        val = (c_char * length)('\x00')
        if self._readCtype(val, address, length):
            raise ReadError(address)
        return val.raw

    def readQword(self, address):
        val = c_uint64(0)
        if self._readCtype(val, address, 8):
            raise ReadError(address)
        return val.value
    def readDword(self, address):
        val = c_uint32(0)
        if self._readCtype(val, address, 4):
            raise ReadError(address)
        return val.value
    def readWord(self, address):
        val = c_uint16(0)
        if self._readCtype(val, address, 2):
            raise ReadError(address)
        return val.value
    def readByte(self, address):
        pageAddress = address & self._pageMask
        if not self._memMap.has_key(pageAddress):
            raise ReadError(address)
        return self.c_uint8.from_address(address).value
    def readAddr(self, address):
        if 4 == self._POINTER_SIZE:
            return self.readDword(address)
        else:
            return self.readQword(address)

    def isAddressValid(self, address):
        pageAddress = address & self._pageMask
        return self._memMap.has_key(pageAddress)

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

    def writeMemory(self, address, data):
        length = len(data)
        startPage   = address & self._pageMask
        endPage     = (address + length) & self._pageMask
        if not self._memMap.has_key(startPage):
            raise WriteError(address)
        if endPage != startPage and not self._memMap.has_key(endPage):
            raise WriteError(address)
        dataPtr = c_char_p(data)
        self._memcpy(address, byref(dataPtr), length)

    def writeQword(self, address, value):
        self.writeMemory(address, pack('Q', value))
    def writeDword(self, address, value):
        self.writeMemory(address, pack('L', value))
    def writeWord(self, address, value):
        self.writeMemory(address, pack('H', value))
    def writeByte(self, address, value):
        self.writeMemory(address, chr(value))
    def writeAddr(self, address, value):
        if 4 == self._POINTER_SIZE:
            self.writeDword(address, value)
        else:
            self.writeQword(address, value)



