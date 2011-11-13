#
#   Interfaces.py
#
#   Interfaces - Defines interfaces for nativDebugging
#   https://svn3.xp-dev.com/svn/nativDebugging/
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2011  Assaf Nativ

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

from abc import ABCMeta, abstractmethod
from .Utile import *

class DebuggerInterface( object ):
    """ Pure Interface for Debugger """
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def __del__(self):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def attach(self):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def detach(self):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def g(self):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def bpx(self, address):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def bpl(self):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def bpc(self, index):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def bpd(self, index):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def bpe(self, index):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def r(self):
        raise NotImplementedError("Pure function call")


class GUIDisplayInterface( object ):
    """ Pure Interface for GUI display """
    __metaclass__ = ABCMeta

    @abstractmethod
    def hexDisplay(self, address, length):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def mapDisplay(self, address, length, colorMap):
        raise NotImplementedError("Pure function call")


class ReadError( Exception ):
    def __init__(self, address):
        self.address = address
        Exception.__init__(self)

class MemReaderInterface( object ):
    """ Pure Interface for Debugger """
    __metaclass__ = ABCMeta

    @abstractmethod
    def readAddr(self, addr):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def readQword(self, addr):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def readDword(self, addr):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def readWord(self, addr):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def readByte(self, addr):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def readMemory(self, addr, length):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def readString(self, addr, isUnicode):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def isAddressValid(self, addr):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def resolveOffsetsList(self, start, offsetsList):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def getPointerSize(self):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def getDefaultDataSize(self):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def getEndianity(self):
        """ Returns either '<' or '>' (same format as in the struct module)
        <: little-endian, std. size & alignment
        >: big-endian, std. size & alignment
        """
        raise NotImplementedError("Pure function call")

class MemWriterInterface( object ):
    """ Pure Interface for Debugger """
    __metaclass__ = ABCMeta

    @abstractmethod
    def writeAddr(self, addr, value):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def writeQword(self, addr, value):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def writeDword(self, addr, value):
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def writeWord(self, addr, value):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def writeByte(self, addr, value):
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def writeMemory(self, addr, data):
        raise NotImplementedError("Pure function call")
    
