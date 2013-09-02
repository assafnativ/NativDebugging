#
#   Interfaces.py
#
#   Interfaces - Defines interfaces for nativDebugging
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

from abc import ABCMeta, abstractmethod
from .Utile import *

class DebuggerInterface( object ):
    """ Pure Interface for Debugger """
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def __del__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def attach(self):
        """ Pure virtual 
        This function should set a new connection to a target process.
        Note: The signeture of the function change from platform to platform and from one implmentation to another. For example in one case it would take process id, and on another a process name. """
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def detach(self):
        """ Pure virtual 
        Disconnecting from debugged process, or closing connection. Should be less aggrassive than __del__ """
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def run(self):
        """ Pure virtual
        Make debuggee run"""
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def breakpointSet(self, address):
        """ Pure virtual
        Set a breakpoint"""
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def breakpointsList(self):
        """ Pure virtual
        Show list of breakpoints """
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def breakpointRemove(self, index):
        """ Pure virtual
        Remove a specific breakpoint"""
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def breakpointDisable(self, index):
        """ Pure virtual
        Disable specific breakpoint"""
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def breakpointEnable(self, index):
        """ Pure virtual
        Enable specific breakpoint"""
        raise NotImplementedError("Pure function call")
    
    @abstractmethod
    def contextShow(self):
        """ Pure virtual
        Show current context of debuggeee, should list all registers and current thread and stuff"""
        raise NotImplementedError("Pure function call")


class GUIDisplayInterface( object ):
    """ Pure Interface for GUI display """
    __metaclass__ = ABCMeta

    @abstractmethod
    def hexDisplay(self, address, length):
        """ Display hex dump """
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def mapDisplay(self, address, length, colorMap):
        """ Display visual bits map of memory """
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

class WriteError( Exception ):
    def __init__(self, address):
        self.address = address
        Exception.__init__(self)

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
    
