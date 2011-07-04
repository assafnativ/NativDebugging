#
#   ExternalMemoryReader.py
#
#   ExternalMemoryReader - Remote process memory inspection python module
#       that uses an external program to read memory.
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

from .MemReaderBaseWin import *
from ..GUIDisplayBase import *
import os
import struct
import subprocess

def attach(targetProcessId, platform):
    return ExternalMemoryReader(targetProcessId, platform)

class ExternalMemoryReader( MemReaderBaseWin, GUIDisplayBase ):
    PLATFORM_X86 = 'x86'
    PLATFORM_AMD64 = 'AMD64'
    PLATFORM_IA64  = 'Ia64'
    SUPPORTED_PLATFORMS = [PLATFORM_X86, PLATFORM_AMD64, PLATFORM_IA64]
    EXTERNAL_READER     = 'memReader%s.exe'
    def __init__( self, targetProcessId, platform=PLATFORM_X86 ):
        MemReaderBase.__init__(self)
        self._processId = targetProcessId
        if platform not in self.SUPPORTED_PLATFORMS:
            raise Exception("Platform %s note supported only %s are supported" % (platform, `self.SUPPORTED_PLATFORMS`))
        self._platform = platform
        self._externalReader = os.path.join(os.path.dirname(__file__), self.EXTERNAL_READER % platform)
        self.reader = subprocess.Popen(
                [
                    self._externalReader,
                    '%d' % targetProcessId ],
                stdin   = subprocess.PIPE,
                stdout  = subprocess.PIPE,
                stderr  = subprocess.STDOUT )
        if platform == self.PLATFORM_X86:
            self._pointerSize = 4
        elif platform == self.PLATFORM_IA64 or self.platform == self.PLATFORM_AMD64:
            self._pointerSize = 8

    def __del__(self):
        self.__detach()

    def detach(self):
        del(self)

    def __detach__(self):
        self.reader.stdin.write('0 0' + os.linesep)
        self.reader.communicate()

    def getPointerSize(self):
        return self._pointerSize

    def getDefaultDataSize(self):
        return 4

    def readMemory(self, address, length):
        self.reader.stdin.write('%x %x%s' % (address, length, os.linesep))
        value = self.reader.stdout.readline()
        if 'Invalid' in value:
            raise Exception('Read from 0x%x of 0x%x bytes failed. Returned code %s' % (address, length, value))
        value = value.strip()
        value = value.decode('hex')
        if len(value) != length:
            raise Exception('Read only 0x%x bytes out of 0x%x from address 0x%x' % (len(value), length, address))
        return value

    def readQword(self, address):
        return struct.unpack('Q', self.readMemory(address, 8))[0]

    def readDword(self, address):
        return struct.unpack('L', self.readMemory(address, 4))[0]

    def readWord(self, address):
        return struct.unpack('H', self.readMemory(address, 2))[0]

    def readByte(self, address):
        return ord(self.readMemory(address, 1))

    def readAddr(self, address):
        if 4 == self._POINTER_SIZE:
            return self.readDword(address)
        else:
            return self.readQword(address)

    def isAddressValid(self, address):
        if self.PLATFORM_X86 == self._platform:
            if (0 == (0xffff0000 & address)) or (0 != (0x80000000 & address)):
                return False
        elif self.PLATFORM_AMD64 == self._platform:
            if (0xfffff80000000000 & address) or (0 == (0xffffffffffff0000 & address)):
                return False
        elif self.PLATFORM_IA64 == self._platform:
            if (0xfffff80000000000 & address) or (0 == (0xffffffffffff0000 & address)):
                return False
        return True

    def readString(self, address):
        result = ''
        while True:
            c = self.readByte(address)
            address += 1
            if 0x20 <= c and c < 0x80:
                result += chr(c)
            else:
                return result

    def getSupportedPlatfroms( self ):
        return ExternalMemoryReader.SUPPORTED_PLATFORMS


