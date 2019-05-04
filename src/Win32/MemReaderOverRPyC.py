#
#   ExternalMemoryReader.py
#
#   ExternalMemoryReader - Remote process memory inspection python module
#       that uses an external program to read memory.
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

from .MemReaderBaseWin import *
from .MemoryReader import MemoryReader
from .InjectDll import InjectDll
from ..GUIDisplayBase import *
from .ProcessCreateAndAttach import *
from ..Interfaces import ReadError
import os
import struct
import subprocess
import rpyc
import sys
from platform import python_implementation

def attach(target):
    return MemReaderOverRPyCFactory().attach(target)

def createProcess(targetExe):
    return MemReaderOverRPyCFactory().create(targetExe)

class MemReaderOverRPyCFactory( MemoryReader, ProcessCreateAndAttach ):
    def __init__(self):
        self.pythonGateDll = 'pythonGate%s.dll'
        if '32 bit' in python_implementation():
            self.pythonGateDll = self.pythonGateDll % 'x86'
        else:
            self.pythonGateDll = self.pythonGateDll % 'AMD64'

        self.pythonGateDllFullPath = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__), self.pythonGateDll))
        self.pythonGateDllFullPath = self.pythonGateDllFullPath.encode('utf8')

    def attach(self,
            target,
            create_info=None):

        if not isinstance(target, integerTypes):
            raise Exception("Target must be a process id")

        MemoryReader.__init__(self,
                target_process_id=target,
                target_open_handle=None,
                cmd_line=None,
                create_suspended=False,
                create_info=None)
        self.injectDll(self.pythonGateDllFullPath)
        return self._initRemote()

    def create(self,
            cmd_line,
            create_suspended=False,
            create_info=None):

        create_info = create_info or dict()
        create_info.update({
            "WITH_DLL":self.pythonGateDllFullPath})
        MemoryReader.__init__(self,
                target_process_id=None,
                target_open_handle=None,
                cmd_line=cmd_line,
                create_suspended=create_suspended,
                create_info=create_info)
        return self._initRemote()

    def _initRemote(self):
        remote = rpyc.classic.connect("localhost", port=12345)
        remote.modules.sys.stdout = sys.stdout
        remote.modules.sys.stdin = sys.stdin
        remote.modules.sys.stderr = sys.stderr
        remote.execute('from NativDebugging.Win32.SelfInspector import *')
        remoteSelfInspector = remote.eval('attach()')
        remoteSelfInspector.remote = remote
        self.remote = remote
        return remote

