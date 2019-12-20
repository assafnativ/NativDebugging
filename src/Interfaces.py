#
#   Interfaces.py
#
#   Interfaces - Defines interfaces for nativDebugging
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
#

from .Utilities import *

class DebuggerInterface( object ):
    """ Pure Interface for Debugger """
    def __init__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    def __del__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    def attach(self):
        """ Pure virtual
        This function should set a new connection to a target process.
        Note: The signeture of the function change from platform to platform and from one implmentation to another. For example in one case it would take process id, and on another a process name. """
        raise NotImplementedError("Pure function call")

    def detach(self):
        """ Pure virtual
        Disconnecting from debugged process, or closing connection. Should be less aggrassive than __del__ """
        raise NotImplementedError("Pure function call")

    def run(self):
        """ Pure virtual
        Make debuggee run"""
        raise NotImplementedError("Pure function call")

    def breakpointSet(self, address):
        """ Pure virtual
        Set a breakpoint"""
        raise NotImplementedError("Pure function call")

    def breakpointsList(self):
        """ Pure virtual
        Show list of breakpoints """
        raise NotImplementedError("Pure function call")

    def breakpointRemove(self, index):
        """ Pure virtual
        Remove a specific breakpoint"""
        raise NotImplementedError("Pure function call")

    def breakpointDisable(self, index):
        """ Pure virtual
        Disable specific breakpoint"""
        raise NotImplementedError("Pure function call")

    def breakpointEnable(self, index):
        """ Pure virtual
        Enable specific breakpoint"""
        raise NotImplementedError("Pure function call")

    def contextShow(self):
        """ Pure virtual
        Show current context of debuggeee, should list all registers and current thread and stuff"""
        raise NotImplementedError("Pure function call")


class GUIDisplayInterface( object ):
    """ Pure Interface for GUI display """
    def hexDisplay(self, address, length):
        """ Display hex dump """
        raise NotImplementedError("Pure function call")

    def mapDisplay(self, address, length, colorMap):
        """ Display visual bits map of memory """
        raise NotImplementedError("Pure function call")


class ReadError( Exception ):
    def __init__(self, address):
        self.address = address
        Exception.__init__(self)

class MemReaderInterface( object ):
    """ Pure Interface for Debugger """
    READER_DESC = {
            'UInt64' : (8, 'Q'),
             'Int64' : (8, 'q'),
            'UInt32' : (4, 'L'),
             'Int32' : (4, 'L'),
            'UInt16' : (2, 'H'),
             'Int16' : (2, 'h'),
            'UInt8'  : (1, 'B'),
             'Int8'  : (1, 'b') }

    def readAddr(self, addr):
        raise NotImplementedError("Pure function call")

    def readUInt64(self, addr):
        raise NotImplementedError("Pure function call")
    def readInt64(self, addr):
        raise NotImplementedError("Pure function call")
    def readUInt32(self, addr):
        raise NotImplementedError("Pure function call")
    def readInt32(self, addr):
        raise NotImplementedError("Pure function call")
    def readUInt16(self, addr):
        raise NotImplementedError("Pure function call")
    def readInt16(self, addr):
        raise NotImplementedError("Pure function call")
    def readUInt8(self, addr):
        raise NotImplementedError("Pure function call")
    def readInt8(self, addr):
        raise NotImplementedError("Pure function call")

    def readMemory(self, addr, length):
        raise NotImplementedError("Pure function call")

    def readString(self, addr, isUnicode):
        raise NotImplementedError("Pure function call")

    def isAddressValid(self, addr):
        raise NotImplementedError("Pure function call")

    def resolveOffsetsList(self, start, offsetsList):
        raise NotImplementedError("Pure function call")

    def getPointerSize(self):
        raise NotImplementedError("Pure function call")

    def getDefaultDataSize(self):
        raise NotImplementedError("Pure function call")

    def getEndianity(self):
        """ Returns either '<' or '>' (same format as in the struct module)
        <: little-endian, std. size & alignment
        >: big-endian, std. size & alignment
        """
        raise NotImplementedError("Pure function call")

    def dq(self, *args, **kwargs):
        self.readNPrintUInt64(*args, **kwargs)
    def dd(self, *args, **kwargs):
        self.readNPrintUInt32(*args, **kwargs)
    def dw(self, *args, **kwargs):
        self.readNPrintUInt16(*args, **kwargs)
    def db(self, *args, **kwargs):
        self.readNPrintBin(*args, **kwargs)
    def resolveOffset(self, *args, **kwargs):
        self.resolveOffsetsList(*args, **kwargs)
    def rol(self, *args, **kwargs):
        self.resolveOffsetsList(*args, **kwargs)

class WriteError( Exception ):
    def __init__(self, address):
        self.address = address
        Exception.__init__(self)

class MemWriterInterface( object ):
    """ Pure Interface for Debugger """
    def writeAddr(self, addr, value):
        raise NotImplementedError("Pure function call")

    def writeUInt64(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeInt64(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeUInt32(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeInt32(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeUInt16(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeInt16(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeUInt8(self, addr, value):
        raise NotImplementedError("Pure function call")
    def writeInt8(self, addr, value):
        raise NotImplementedError("Pure function call")

    def writeMemory(self, addr, data):
        raise NotImplementedError("Pure function call")

