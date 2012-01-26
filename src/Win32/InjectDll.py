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
from .Win32Structs import *
from .Win32Utile import *
from struct import pack

REMOTE_BUFFER_SIZE = 0x200
MAX_DLL_NAME_LENGTH = 0x100

def printIfVerbose(text, isVerbose):
    if isVerbose:
        print(text)

def inject( process_id, dllName, LoadLibraryA_address=-1, isVerbose=False ):
    if len(dllName) > MAX_DLL_NAME_LENGTH:
        print("Dll name too long")
        return

    adjustDebugPrivileges()

    printIfVerbose("Opening the target process %d" % process_id, isVerbose)
    remoteProcess = \
            OpenProcess(
                        #PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                        win32con.PROCESS_ALL_ACCESS,
                        0,
                        process_id )
    __injectAndExecute(remoteProcess, dllName, LoadLibraryA_address, isVerbose=isVerbose)
    CloseHandle(remoteProcess)
 
def __injectAndExecute( remoteProcess, dllName, LoadLibraryA_address=-1, creationFlags=0, isVerbose=False ):
    printIfVerbose("Allocating memory inside remote process", isVerbose)

    dllName += "\x00"
    remote_buffer_size = len(dllName)

    remote_memory_address = \
        VirtualAllocEx( remoteProcess,
                        None,
                        remote_buffer_size,
                        win32con.MEM_COMMIT,
                        win32con.PAGE_READWRITE ) 
    printIfVerbose("Memory allocated at 0x%x" % remote_memory_address, isVerbose)
    printIfVerbose("Writting the dll name to remote process", isVerbose)
    bytes_written = c_uint(0)
    WriteProcessMemory(
                    remoteProcess,
                    remote_memory_address,
                    dllName,
                    remote_buffer_size,
                    byref(bytes_written))
    if bytes_written.value != remote_buffer_size:
        print("Unable to write to process memory")
        return

    if -1 == LoadLibraryA_address:
        printIfVerbose("Verifing the LoadLibrary proc address", isVerbose)
        kernel32lib = LoadLibrary( "kernel32.dll" )
        LoadLibraryA_address = \
            GetProcAddress( kernel32lib,
                            "LoadLibraryA" )
        printIfVerbose("LoadLibraryA found at 0x%x" % LoadLibraryA_address, isVerbose)
        # We can assume that kernel32 is loaded in the same place in every process
        # because it's the first dll to be loaded in every process

    printIfVerbose("Creating remote thread on LoadLibrary", isVerbose)
    remote_thread_id = c_uint(0)
    remote_thread = CreateRemoteThread( \
                        remoteProcess,
                        None,
                        0,
                        LoadLibraryA_address,
                        remote_memory_address,
                        creationFlags,
                        byref(remote_thread_id) )
    printIfVerbose("Thread %d created" % remote_thread_id.value, isVerbose)
    return remote_thread

def createProcessWithDll(
        cmdLine, 
        dll, 
        securityAttributes=None, 
        threadAttributes=None, 
        inheritHandles=0, 
        creationFlags=win32con.NORMAL_PRIORITY_CLASS, 
        environment=None, 
        currentDirectory=None,
        startupInfo=None,
        processInfo=None,
        isVerbose=False ):

    cmdLine = c_char_p(cmdLine)
    if None == startupInfo:
        startupInfo = STARTUPINFO()
        startupInfo.dwFlags = 0
        startupInfo.wShowWindow = 0x0
        startupInfo.cb = sizeof(STARTUPINFO)
    if None == processInfo:
        processInfo = PROCESS_INFORMATION()
    if None == securityAttributes:
        securityAttributes = SECURITY_ATTRIBUTES()
        securityAttributes.Length = sizeof(SECURITY_ATTRIBUTES)
        securityAttributes.SecDescriptior = None
        securityAttributes.InheritHandle = True
    if None == threadAttributes:
        threadAttributes = SECURITY_ATTRIBUTES()
        threadAttributes.Length = sizeof(SECURITY_ATTRIBUTES)
        threadAttributes.SecDescriptior = None
        threadAttributes.InheritHandle = True
        
    printIfVerbose('Creating process', isVerbose)
    CreateProcess( 
                pchar_NULL,
                cmdLine, 
                byref(securityAttributes),
                byref(threadAttributes),
                TRUE,
                creationFlags | win32con.CREATE_SUSPENDED,
                environment,
                currentDirectory,
                byref(startupInfo),
                byref(processInfo) )
    printIfVerbose('Process created', isVerbose)
    printIfVerbose('Process handle: %d' % processInfo.hProcess, isVerbose)
    printIfVerbose('Process id: %d' % processInfo.dwProcessId, isVerbose)
    printIfVerbose('Thread handle: %d' % processInfo.hThread, isVerbose)
    printIfVerbose('Thread id: %d' % processInfo.dwThreadId, isVerbose)
    remoteThread = __injectAndExecute( processInfo.hProcess, dll, isVerbose=isVerbose, creationFlags=win32con.CREATE_SUSPENDED)
    ResumeThread(processInfo.hThread)
    printIfVerbose('Process resumed', isVerbose)
    ResumeThread(remoteThread)

    return (processInfo.hProcess, processInfo.hThread, processInfo.dwProcessId, processInfo.dwThreadId)





