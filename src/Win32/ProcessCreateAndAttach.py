
from abc import ABCMeta, abstractmethod
from .Win32Structs import *
from .Win32Utilities import *
from ..Utilities import *

class ProcessCreateAndAttach( object ):
    @abstractmethod
    def __init__( self,
            target_process_id=None,
            target_open_handle=None,
            cmd_line=None,
            create_suspended=False,
            create_info=None ):

        if None == create_info:
            create_info = {}
        if   (None != target_open_handle) and (None == target_process_id) and (None == cmd_line):
            self._process = target_open_handle
            self._processId = GetProcessId(self._process)
            target_process_id = self._processId
            self._isSuspended = False
        elif (None == target_open_handle) and (None != target_process_id) and (None == cmd_line):
            adjustDebugPrivileges()
            self._processId = target_process_id
            self._openProcess( target_process_id )
            self._isSuspended = False
        elif (None == target_open_handle) and (None == target_process_id) and (None != cmd_line):
            self._createProcess(cmd_line, create_suspended, create_info)
        self._POINTER_SIZE = sizeof(c_void_p)
        self._is_win64 = self._POINTER_SIZE == 8
        self._DEFAULT_DATA_SIZE = 4
        self._mem_map = None
        sysInfo = SYSTEM_INFO()
        GetSystemInfo(byref(sysInfo))
        self._minVAddress   = sysInfo.lpMinimumApplicationAddress
        self._maxVAddress   = sysInfo.lpMaximumApplicationAddress
        self._pageSize      = sysInfo.dwPageSize
        self._pageSizeMask  = self._pageSize - 1

    def _createProcess(self, cmdLine, createSuspended, createInfo):
        cmdLine = c_wchar_p(cmdLine)
        if 'STARTUPINFO' not in createInfo:
            startupInfo = STARTUPINFO()
            startupInfo.dwFlags = 0
            startupInfo.wShowWindow = 0x0
            startupInfo.cb = sizeof(STARTUPINFO)
        else:
            startupInfo = createInfo['STARTUPINFO']
        processInfo = PROCESS_INFORMATION()
        if 'SECURITY_ATTRIBUTES' not in createInfo:
            securityAttributes = SECURITY_ATTRIBUTES()
            securityAttributes.Length = sizeof(SECURITY_ATTRIBUTES)
            securityAttributes.SecDescriptior = None
            securityAttributes.InheritHandle = True
        else:
            securityAttributes = createInfo['SECURITY_ATTRIBUTES']
        if 'SECURITY_ATTRIBUTES' not in createInfo:
            threadAttributes = SECURITY_ATTRIBUTES()
            threadAttributes.Length = sizeof(SECURITY_ATTRIBUTES)
            threadAttributes.SecDescriptior = None
            threadAttributes.InheritHandle = True
        else:
            threadAttributes = createInfo['SECURITY_ATTRIBUTES']
        currentDirectory = createInfo.get('CURRENT_DIRECTORY', None)
        creationFlags = createInfo.get('CREATION_FLAGS', 0)
        if createSuspended:
            creationFlags |= win32con.CREATE_SUSPENDED
        dllToInject = createInfo.get('WITH_DLL', None)
        if dllToInject:
            creationFlags |= win32con.CREATE_SUSPENDED
            creationFlags |= win32con.CREATE_DEFAULT_ERROR_MODE

        CreateProcess(
                    None,
                    cmdLine,
                    byref(securityAttributes),
                    byref(threadAttributes),
                    TRUE,
                    creationFlags,
                    createInfo.get('ENVIRONMENT', None),
                    currentDirectory,
                    byref(startupInfo),
                    byref(processInfo) )
        self._process         = processInfo.hProcess
        self._processId       = processInfo.dwProcessId
        self._mainThread      = processInfo.hThread
        self._mainThreadId    = processInfo.dwThreadId
        self._currentThread   = processInfo.hThread
        self._currentThreadId = processInfo.dwThreadId
        self._isSuspended = createSuspended
        if dllToInject:
            self.injectDllPatchImportsTable(dllToInject)
        if not createSuspended:
            ResumeThread(self._mainThread)

    def _closeProcess( self ):
        if hasattr(self, '_process') and self._process:
            CloseHandle( self._process )

    def _openProcess( self, target_pid ):
        bytes_read = c_uint32(0)
        self._process = OpenProcess(
                self.REQUIRED_ACCESS | win32con.PROCESS_DUP_HANDLE,
                0,
                target_pid )

    def resumeSuspendedProcess(self):
        if self._isSuspended:
            self._isSuspended = False
            ResumeThread(self._mainThread)

