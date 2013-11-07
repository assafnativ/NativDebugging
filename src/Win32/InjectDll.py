#
#   InjectDll.py
#
#   InjectDll - Dll injection module for python
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

# Imports
from abc import ABCMeta, abstractmethod
from .Win32Structs import *
from .MemReaderBaseWin import *

class InjectDll( object ):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")
    @abstractmethod
    def writeMemory(self, remoteAddress, data):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")
    @abstractmethod
    def findProcAddress(self, module, proc):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    def injectDll(self, dllName, LoadLibraryA_address=None, creationFlags=0):
        if dllName[-1] != '\x00':
            dllName += "\x00"
        if None == LoadLibraryA_address:
            LoadLibraryA_address = self.findProcAddress("kernel32.dll", "LoadLibraryA")
        return self.createRemoteThreadAtAddress(LoadLibraryA_address, param=dllName, creationFlags=creationFlags)

    def createRemoteThreadAtAddress(self, remoteAddress, param=None, creationFlags=0):
        if isinstance(param, str):
            param = self._allocateAndWrite( param )
        elif isinstance(param, (int, long)):
            pass
        elif None==param:
            param = 0
        else:
            raise Exception("Unsupported param")

        remote_thread_id = c_uint32(0)
        remote_thread = CreateRemoteThread( \
                            self._process,
                            None,
                            0,
                            remoteAddress,
                            param,
                            creationFlags,
                            byref(remote_thread_id) )
        return remote_thread, remote_thread_id.value

    def _allocateAndWrite(self, data):
        remoteAddress = self.allocateRemote(len(data))
        self.writeMemory(remoteAddress, data)
        return remoteAddress

    def allocateRemote(self, length):
        remoteAddress = \
            VirtualAllocEx( self._process,
                            None,
                            length,
                            win32con.MEM_COMMIT,
                            win32con.PAGE_READWRITE ) 
        return remoteAddress

    def injectRPyC(self, pythonDll=None):
        if None == pythonDll:
            import sys
            pythonDll = 'python%d%d.dll' % (sys.version_info.major, sys.version_info.minor)
        pythonAddr = injectDll(pythonDll)


