
from abc import ABCMeta, abstractmethod
from .Win32Structs import *
from .Win32Utile import *
from ..Utile import *

class ProcessCreateAndAttach( object ):
    @abstractmethod
    def __init__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    def createOrAttachProcess( self, \
            target_process_id=None, \
            target_open_handle=None, \
            cmd_line=None, \
            create_suspended=False, \
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
        if not self._is64Windows:
            self._POINTER_SIZE = 4
            self._is64Target = False
        else:
            if self._isTargetWow64():
                self._is64Target = False
                self._POINTER_SIZE = 4
            else:
                self._is64Target = True
                self._POINTER_SIZE = 8
        self._DEFAULT_DATA_SIZE = 4
        self._mem_map = None
        sysInfo = SYSTEM_INFO()
        GetSystemInfo(byref(sysInfo))
        self._minVAddress   = sysInfo.lpMinimumApplicationAddress
        self._maxVAddress   = sysInfo.lpMaximumApplicationAddress
        self._pageSize      = sysInfo.dwPageSize
        self._pageSizeMask  = self._pageSize - 1

    def _isTargetWow64(self):
        isWow64 = c_uint32(0)
        IsWow64Process(self._process, byref(isWow64))
        return 0 != isWow64.value

    def _createProcess(self, cmdLine, createSuspended, createInfo):
        cmdLine = c_char_p(cmdLine)
        if 'STARTUPINFO' not in createInfo:
            startupInfo = STARTUPINFO()
            startupInfo.dwFlags = 0
            startupInfo.wShowWindow = 0x0
            startupInfo.cb = sizeof(STARTUPINFO)
        else:
            startupInfo = createInfo['STARTUPINFO']
        if 'PROCESSINFO' not in createInfo:
            processInfo = PROCESS_INFORMATION()
        else:
            processInfo = createInfo['PROCESSINFO']
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
        if 'CURRENT_DIRECTORY' not in createInfo:
            currentDirectory = None
        else:
            currentDirectory = createInfo['CURRENT_DIRECTORY']
        if 'ENVIRONMENT' not in createInfo:
            environment = None
        else:
            environment = createInfo['ENVIRONMENT']
        if 'CREATION_FLAGS' in createInfo:
            creationFlags = createInfo['CREATION_FLAGS']
        else:
            creationFlags = 0
        if createSuspended:
            creationFlags |= win32con.CREATE_SUSPENDED
        if 'WITH_DLL' in createInfo:
            creationFlags |= win32con.CREATE_SUSPENDED
            dllToInject = createInfo['WITH_DLL']
        else:
            dllToInject = None

        CreateProcess( 
                    None,
                    cmdLine, 
                    byref(securityAttributes),
                    byref(threadAttributes),
                    TRUE,
                    creationFlags,
                    environment,
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
            threadHandle = self.injectDll(dllToInject)
            ResumeThread(threadHandle)
            if not createSuspended:
                self.resumeSuspendedProcess()

    def _closeProcess( self ):
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

