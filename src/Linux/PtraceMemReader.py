#
#   PtraceMemReader.py
#
#   PtraceMemReader - Attach and read memory on *nix platforms
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

import os
from struct import pack
from ctypes import c_char,c_long, c_void_p, c_int8, c_int16, c_int32, c_int64, c_uint8, c_uint16, c_uint32, c_uint64, cdll, sizeof,c_ulong
import re

from ..Interfaces import ReadError
from ..MemReaderBase import *
from ..Utilities import *


class MemInfo(object):
    def __init__(self, start, end, permissions, offset, dev, inode, pathName):
        '''
        contains all the attributes according to /proc/$pid/maps
        '''
        self.start = start
        self.end = end

        self.size = self.end - self.start

        self.permissions = permissions

        self.read    = permissions[0] == 'r'
        self.write   = permissions[1] == 'w'
        self.execute = permissions[2] == 'x'
        self.private = permissions[3] == 'p'

        self.offset = offset
        self.dev = dev
        self.inode = inode
        self.pathName = pathName.strip()

    def isRead(self):
        return self.read
    def isWrite(self):
        return self.write
    def isExecute(self):
        return self.execute
    def isPrivate(self):
        return self.private

    def __repr__(self):

        return "MemInfo:0x%x-0x%x(size=0x%x) (0x%x)(%s) (%s)" % (self.start,self.end,self.size,self.offset,self.permissions,self.pathName)

def attach(pid):
    # memInfo: (memId, baseAddress, size)
    return PtraceMemReader(pid)

class PtraceMemReader( MemReaderBase ):
    def __init__(self, pid):
        MemReaderBase.__init__(self)

        self.pid = pid
        self.isAttached = False

        self._POINTER_SIZE = sizeof(c_void_p)
        self._DEFAULT_DATA_SIZE = 4

        self._LONG_SIZE = sizeof(c_ulong)

        # This is alwasy little-endian.
        # Show me one *nix machine with Python ctypes that is not little-endian.
        self._ENDIANITY = '<'

        libc = cdll.LoadLibrary("libc.so.6")

        # long ptrace(enum __ptrace_request request, pid_t pid,void*addr, void *data);
        # pid_t = 4
        self.ptrace = libc.ptrace
        self.ptrace.argtypes = [c_ulong, c_ulong, c_ulong, c_ulong]
        self.ptrace.restype = c_ulong

        self.PTRACE_TRACEME = 0x0

        self.PTRACE_PEEKTEXT = 1 # normal use
        #self.PTRACE_PEEKDATA = 2 # same as PEEKTEXT
        self.PTRACE_PEEKUSER = 3 # should not be used

        self.PTRACE_POKETEXT = 4
        self.PTRACE_POKEDATA = 5
        self.PTRACE_POKEUSER = 6

        self.PTRACE_CONT = 7
        self.PTRACE_KILL = 8
        self.PTRACE_SINGLESTEP = 9

        self.PTRACE_ATTACH = 0x10
        self.PTRACE_DETACH = 0x11

        self.memMap = []

        # attach to process
        ret = self.ptrace(self.PTRACE_ATTACH, self.pid, 0, 0)
        if 0 != ret:
            print 'ret = %d (0x%x)' % (ret,ret)
            raise Exception('error - could not ptrace attach to pid : %d' % self.pid)

        self.isAttached = True

        print 'reading memory regions...'
        self.readMemoryRegions()


    def getRegionsByPathName(self,pathStr,verbose=True):
        '''
        returns all the memory regions by using a specified name (regexp)
        '''

        found = []

        for reg in self.memMap:
            if True == reg.isRead() and None != re.match('.*%s.*' % pathStr, reg.pathName, re.I | re.M | re.S):
                found.append(reg)

                if verbose:
                    print '\n%s' % str(reg)

        if verbose:
            print 'found %d matches for pathStr = %s' % (len(found),pathStr)

        return found


    def readMemoryRegions(self):
        # read all the process memory regions

        self.memMap = []

        if False == os.path.exists('/proc/%d/maps' % self.pid):
            raise Exception('PtraceMemReader - could not find process %d map file' % self.pid)


        processRegions = open('/proc/%d/maps' % self.pid,'r').readlines()

        for line in processRegions:
                # start, end, permissions, offset, dev, inode, pathName
                m = re.match('^(\w+)\-(\w+) ([\w-]+) (\w+) ([\w\:]+) (\w+)\s*(.*)',line)

                # start,end,permissions,offsets,dev,inode,pathName = 7 parts

                if None == m or 7 != len(m.groups()):

                    raise Exception('could not parse line : %s' % line)

                parts = m.groups()

                start = long(parts[0],16)
                end = long(parts[1],16)
                permissions = parts[2]
                offset = long(parts[3],16)
                dev = parts[4]
                inode = parts[5]
                pathName = parts[6]

                self.memMap.append(MemInfo(start, end, permissions, offset, dev, inode, pathName))

        print '\t read %d regions for pid %d' % (len(self.memMap),self.pid)

    def getMemoryMap(self):
        memMap = {}
        for mem in self.memMap:
            memMap[mem.start] = ('%d' % mem.pathName, mem.size, 0xffffffff)
        return memMap

    def __del__(self):
        self.__detach()

    def detach(self):
        self.__detach()
        del(self)

    def __detach(self):
        if False == self.isAttached:
            return True

        ret = self.ptrace(self.pid,self.PTRACE_DETACH,0,0)

        return 0 == ret


    def getPointerSize(self):
        return self._POINTER_SIZE

    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE

    def getEndianity(self):
            return self._ENDIANITY

    def readLong(self,address):
        ret_long = self.ptrace(self.PTRACE_PEEKTEXT, self.pid, address, 0)

        return ret_long

    def readMemory(self, startAddress, length):
        result = ''
        if 8 == self._LONG_SIZE:
            leftOvers = length % 8
            endAddress = startAddress + length - leftOvers
            for address in range(startAddress, endAddress, 8):
                result += struct.pack('Q', self.readLong(address))
            length = leftOvers
            startAddress = endAddress
        if 4 < length:
            leftOvers = length % 4
            endAddress = startAddress + length - leftOvers
            for address in range(startAddress, endAddress, 4):
                result += struct.pack('L', self.readUInt32(addresss))
            length = leftOvers
            startAddress = endAddress
        if 2 <= length:
            result += strcut.pack('H', self.readUInt16(startAddress))
            startAddress += 2
            length -= 2
        if 1 == length:
            result += chr(self.readUInt8(startAddress))
        return result

    def readUInt64(self, address):
        if 8 == self._LONG_SIZE:
            return self.readLong(address)
        elif 4 == self._LONG_SIZE:
            self.readLong(address) + (self.readLong(address + 4) << 32)
            ret_long1 = self.readLong(address)
            ret_long2 = self.readLong(address + 4)

            # TODO : verify this for 32bit and endianiness
            return (ret_long1 << 32) | ret_long2
    def readInt64(self, address):
        val = self.readUInt64(address)
        if 0x8000000000000000 <= val:
            return -(0x10000000000000000 - val)
        return val

    def readUInt32(self, address):
        return self.readLong(address) & 0xFFFFFFFF
    def readInt32(self, address):
        val = self.readUInt32(address)
        if 0x80000000 <= val:
            return -(0x100000000 - val)
        return val

    def readUInt16(self, address):
        return self.readLong(address) & 0xFFFF
    def readInt16(self, address):
        val = self.readUInt16(address)
        if 0x8000 <= val:
            return -(0x10000 - val)
        return val

    def readUInt8(self, address):
        return self.readLong(address) & 0xFF
    def readInt8(self, address):
        val = self.readUInt8(address)
        if 0x80 <= val:
            return -(0x100 - val)
        return val

    def readAddr(self, address, isLocalAddress=False):
        if self._LONG_SIZE != self._POINTER_SIZE:
            raise Exception('unmatched long and pointer size')

        return self.readLong(address)

    def getRegion(self,addr):
        '''
        returns the memory regions for a given address
        '''
        for region in self.memMap:
            if addr >= region.start and addr < region.end:
                return region
        # Region not found
        return None

    def isAddressValid(self, address, isLocalAddress=False):
        # TODO : check alignment
        for memInfo in self.memMap:
            if memInfo.isRead() and address >= memInfo.start and address <= memInfo.end:
                return True
        return False

