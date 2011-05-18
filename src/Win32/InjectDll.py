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

def printIfVerbos(text, isVerbos):
    if isVerbos:
        print(text)

def inject( process_id, dllName, LoadLibraryA_address=-1, isVerbos=False ):
    if len(dllName) > MAX_DLL_NAME_LENGTH:
        print("Dll name too long")
        return

    adjustDebugPrivileges()

    printIfVerbos("Opening the target process %d" % process_id, isVerbos)
    remoteProcess = \
            OpenProcess(
                        #PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                        win32con.PROCESS_ALL_ACCESS,
                        0,
                        process_id )
    __injectAndExecute(remoteProcess, dllName, LoadLibraryA_address, isVerbos=isVerbos)
    CloseHandle(remoteProcess)
 
def __injectAndExecute( remoteProcess, dllName, LoadLibraryA_address=-1, creationFalgs=0, isVerbos=False ):
    printIfVerbos("Allocating memory inside remote process", isVerbos)
    remote_memory_address = \
        VirtualAllocEx( remoteProcess,
                        None,
                        REMOTE_BUFFER_SIZE,
                        win32con.MEM_COMMIT,
                        win32con.PAGE_EXECUTE_READWRITE )
    printIfVerbos("Memory allocated at 0x%x" % remote_memory_address, isVerbos)
    printIfVerbos("Writting the dll name to remote process", isVerbos)
    bytes_written = c_uint(0)
    WriteProcessMemory(
                    remoteProcess,
                    remote_memory_address,
                    dllName + '\x00',
                    len(dllName) + 1,
                    byref(bytes_written))
    if bytes_written.value != (len(dllName) + 1):
        print("Unable to write to process memory")
        return

    if -1 == LoadLibraryA_address:
        printIfVerbos("Verifing the LoadLibrary proc address", isVerbos)
        kernel32lib = LoadLibrary( "kernel32.dll" )
        LoadLibraryA_address = \
            GetProcAddress( kernel32lib,
                            "LoadLibraryA" )
        printIfVerbos("LoadLibraryA found at 0x%x" % LoadLibraryA_address, isVerbos)
        # We can assume that kernel32 is loaded in the same place in every process
        # because it's the first dll to be loaded in every process

    printIfVerbos('Generating loading code', isVerbos)
    code = '\x68'       # Push
    code += pack('=l', remote_memory_address)
    code += '\xb8'      # mov eax,
    code += pack('=l', LoadLibraryA_address)
    code += '\xff\xd0'  # call eax
    code += '\x3c\xc0'  # xor eax,eax
    code += '\xc3'      # retn
    WriteProcessMemory(
            remoteProcess,
            remote_memory_address + MAX_DLL_NAME_LENGTH,
            code,
            len(code),
            byref(bytes_written))
    if bytes_written.value != len(code):
        print('Unable to write code')
        return

    printIfVerbos("Creating remote thread on LoadLibrary", isVerbos)
    remote_thread_id = c_uint(0)
    remote_thread = CreateRemoteThread( \
                        remoteProcess,
                        None,
                        0,
                        remote_memory_address + MAX_DLL_NAME_LENGTH,
                        remote_memory_address,
                        creationFalgs,
                        byref(remote_thread_id) )
    printIfVerbos("Thread %d created" % remote_thread_id.value, isVerbos)
    return remote_thread

def createProcessWithDll(
        cmdLine, 
        dll, 
        securityAttributes=None, 
        threadAttributes=None, 
        inheritHandles=0, 
        creationFalgs=win32con.NORMAL_PRIORITY_CLASS, 
        environment=None, 
        currentDirectory=None,
        startupInfo=None,
        processInfo=None,
        isVerbos=False ):

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
        
    printIfVerbos('Creating process', isVerbos)
    CreateProcess( 
                pchar_NULL,
                cmdLine, 
                byref(securityAttributes),
                byref(threadAttributes),
                TRUE,
                creationFalgs | win32con.CREATE_SUSPENDED,
                environment,
                currentDirectory,
                byref(startupInfo),
                byref(processInfo) )
    printIfVerbos('Process created', isVerbos)
    printIfVerbos('Process handle: %d' % processInfo.hProcess, isVerbos)
    printIfVerbos('Process id: %d' % processInfo.dwProcessId, isVerbos)
    printIfVerbos('Thread handle: %d' % processInfo.hThread, isVerbos)
    printIfVerbos('Thread id: %d' % processInfo.dwThreadId, isVerbos)
    remoteThread = __injectAndExecute( processInfo.hProcess, dll, isVerbos=isVerbos )
    ResumeThread(processInfo.hThread)
    printIfVerbos('Process resumed', isVerbos)
    ResumeThread(remoteThread)

    return (processInfo.hProcess, processInfo.hThread, processInfo.dwProcessId, processInfo.dwThreadId)



