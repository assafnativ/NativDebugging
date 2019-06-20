#
#   InjectDll.py
#
#   InjectDll - Dll injection module for python
#   https://github.com/assafnativ/NativDebugging
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2019  Assaf Nativ
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

# Imports
from abc import ABCMeta, abstractmethod
from .Win32Structs import *
from .MemReaderBaseWin import *
from .MemoryReader import MemoryReader
from .DetoursWrapper import Detours
from ..Utilities import integer_types
from builtins import range
import struct

def attach():
    return SelfReader()

class SelfReader( MemoryReader, Detours ):
    def __init__(self):
        MemReaderBase.__init__(self)
        Detours.__init__(self)
        self._POINTER_SIZE = struct.calcsize('P')
        self._DEFAULT_DATA_SIZE = 4
        self._process = GetCurrentProcess()

    def readQword( self, address ):
        return c_uint64.from_address(address).value

    def readDword( self, address ):
        return c_uint32.from_address(address).value

    def readWord( self, address ):
        return c_uint16.from_address(address).value

    def readByte( self, address ):
        return c_uint8.from_address(address).value

    def readAddr( self, address ):
        return c_void_p.from_address(address).value

    def readMemory( self, address, length ):
        return c_ARRAY(c_char, length).from_address(address).raw

    def readString( self, address, maxSize=None, isUnicode=False ):
        if not maxSize:
            maxSize = -1
        if isUnicode:
            return wstring_at(address, maxSize)
        else:
            return string_at( address, maxSize)
