#
#   win32structs.py
#
#   pyMint - Remote process memory inspection python module
#   https://code.google.com/p/pymint/
#   Nativ.Assaf+pyMint@gmail.com
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

# ImPoRtS

# Import win32con
class win32con( object ):
    def __init__( self ):
        pass
win32con.NULL = 0
win32con.TOKEN_QUERY                    = 8
win32con.TOKEN_ADJUST_PRIVILEGES        = 32
win32con.PROCESS_VM_OPERATION           = 8
win32con.PROCESS_VM_READ                = 16
win32con.PROCESS_VM_WRITE               = 32
win32con.PROCESS_DUP_HANDLE             = 64
win32con.PROCESS_QUERY_INFORMATION      = 1024
win32con.PROCESS_ALL_ACCESS             = 0x1f0fff
win32con.MEM_COMMIT                     = 0x1000
win32con.PAGE_EXECUTE_READWRITE         = 0x40
win32con.ObjectBasicInformation         = 0
win32con.ObjectNameInformation          = 1
win32con.ObjectTypeInformation          = 2
win32con.ObjectAllTypesInformation      = 3
win32con.ObjectHandleInformation        = 4
win32con.STATUS_SUCCESS                 = 0x00000000
win32con.STATUS_INFO_LENGTH_MISMATCH    = 0xc0000004
win32con.STATUS_BUFFER_OVERFLOW         = 0x80000005
win32con.SystemHandleInformation        = 16
win32con.STANDARD_RIGHTS_REQUIRED       = 0x000f0000
win32con.DBG_CONTINUE                   = 0x00010002
win32con.DBG_EXCEPTION_NOT_HANDLED      = 0x00010001
win32con.DBG_CONTROL_C                  = 0x40010005
win32con.DBG_CONTROL_BREAK              = 0x40010008
win32con.INFINITE                       = 0xFFFFFFFF
win32con.CONTEXT_i386                   = 0x00010000
win32con.CONTEXT_CONTROL                = 0x00000001
win32con.CONTEXT_INTEGER                = 0x00000002
win32con.CONTEXT_SEGMENTS               = 0x00000004
win32con.CONTEXT_FLOATING_POINT         = 0x00000008
win32con.CONTEXT_DEBUG_REGISTERS        = 0x00000010
win32con.CONTEXT_EXTENDED_REGISTERS     = 0x00000020
win32con.CONTEXT_FULL                   = 0x00000007
win32con.CW_USEDEFAULT                  = -0x80000000
win32con.STARTF_USESIZE                 = 2
win32con.DEBUG_PROCESS                  = 1
win32con.NORMAL_PRIORITY_CLASS          = 0x20
win32con.EXCEPTION_DEBUG_EVENT          = 1
win32con.CREATE_THREAD_DEBUG_EVENT      = 2
win32con.CREATE_PROCESS_DEBUG_EVENT     = 3
win32con.EXIT_THREAD_DEBUG_EVENT        = 4
win32con.EXIT_PROCESS_DEBUG_EVENT       = 5
win32con.LOAD_DLL_DEBUG_EVENT           = 6
win32con.UNLOAD_DLL_DEBUG_EVENT         = 7
win32con.OUTPUT_DEBUG_STRING_EVENT      = 8
win32con.CREATE_SUSPENDED               = 4
win32con.PAGE_READWRITE                 = 4
STATUS_WAIT_0                    = 0    
STATUS_ABANDONED_WAIT_0          = 128    
STATUS_USER_APC                  = 192    
STATUS_TIMEOUT                   = 258    
STATUS_PENDING                   = 259    
STATUS_SEGMENT_NOTIFICATION      = 1073741829    
STATUS_GUARD_PAGE_VIOLATION      = -2147483647    
STATUS_DATATYPE_MISALIGNMENT     = -2147483646    
STATUS_BREAKPOINT                = -2147483645    
STATUS_SINGLE_STEP               = -2147483644    
STATUS_ACCESS_VIOLATION          = -1073741819    
STATUS_IN_PAGE_ERROR             = -1073741818    
STATUS_INVALID_HANDLE            = -1073741816    
STATUS_NO_MEMORY                 = -1073741801    
STATUS_ILLEGAL_INSTRUCTION       = -1073741795    
STATUS_NONCONTINUABLE_EXCEPTION  = -1073741787    
STATUS_INVALID_DISPOSITION       = -1073741786    
STATUS_ARRAY_BOUNDS_EXCEEDED     = -1073741684    
STATUS_FLOAT_DENORMAL_OPERAND    = -1073741683    
STATUS_FLOAT_DIVIDE_BY_ZERO      = -1073741682    
STATUS_FLOAT_INEXACT_RESULT      = -1073741681    
STATUS_FLOAT_INVALID_OPERATION   = -1073741680    
STATUS_FLOAT_OVERFLOW            = -1073741679    
STATUS_FLOAT_STACK_CHECK         = -1073741678    
STATUS_FLOAT_UNDERFLOW           = -1073741677    
STATUS_INTEGER_DIVIDE_BY_ZERO    = -1073741676    
STATUS_INTEGER_OVERFLOW          = -1073741675    
STATUS_PRIVILEGED_INSTRUCTION    = -1073741674    
STATUS_STACK_OVERFLOW            = -1073741571    
STATUS_CONTROL_C_EXIT            = -1073741510    
win32con.EXCEPTION_ACCESS_VIOLATION          = STATUS_ACCESS_VIOLATION
win32con.EXCEPTION_DATATYPE_MISALIGNMENT     = STATUS_DATATYPE_MISALIGNMENT
win32con.EXCEPTION_BREAKPOINT                = STATUS_BREAKPOINT
win32con.EXCEPTION_SINGLE_STEP               = STATUS_SINGLE_STEP
win32con.EXCEPTION_ARRAY_BOUNDS_EXCEEDED     = STATUS_ARRAY_BOUNDS_EXCEEDED
win32con.EXCEPTION_FLT_DENORMAL_OPERAND      = STATUS_FLOAT_DENORMAL_OPERAND
win32con.EXCEPTION_FLT_DIVIDE_BY_ZERO        = STATUS_FLOAT_DIVIDE_BY_ZERO
win32con.EXCEPTION_FLT_INEXACT_RESULT        = STATUS_FLOAT_INEXACT_RESULT
win32con.EXCEPTION_FLT_INVALID_OPERATION     = STATUS_FLOAT_INVALID_OPERATION
win32con.EXCEPTION_FLT_OVERFLOW              = STATUS_FLOAT_OVERFLOW
win32con.EXCEPTION_FLT_STACK_CHECK           = STATUS_FLOAT_STACK_CHECK
win32con.EXCEPTION_FLT_UNDERFLOW             = STATUS_FLOAT_UNDERFLOW
win32con.EXCEPTION_INT_DIVIDE_BY_ZERO        = STATUS_INTEGER_DIVIDE_BY_ZERO
win32con.EXCEPTION_INT_OVERFLOW              = STATUS_INTEGER_OVERFLOW
win32con.EXCEPTION_PRIV_INSTRUCTION          = STATUS_PRIVILEGED_INSTRUCTION
win32con.EXCEPTION_IN_PAGE_ERROR             = STATUS_IN_PAGE_ERROR
win32con.EXCEPTION_ILLEGAL_INSTRUCTION       = STATUS_ILLEGAL_INSTRUCTION
win32con.EXCEPTION_NONCONTINUABLE_EXCEPTION  = STATUS_NONCONTINUABLE_EXCEPTION
win32con.EXCEPTION_STACK_OVERFLOW            = STATUS_STACK_OVERFLOW
win32con.EXCEPTION_INVALID_DISPOSITION       = STATUS_INVALID_DISPOSITION
win32con.EXCEPTION_GUARD_PAGE                = STATUS_GUARD_PAGE_VIOLATION
win32con.EXCEPTION_INVALID_HANDLE            = STATUS_INVALID_HANDLE
win32con.CONTROL_C_EXIT                      = STATUS_CONTROL_C_EXIT
win32con.PE_POINTER_OFFSET                   = 0x3c
win32con.PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET = 0x14
win32con.PE_SIZEOF_NT_HEADER                 = 0x18
win32con.PE_NUM_OF_SECTIONS_OFFSET           = 0x06
win32con.IMAGE_SIZEOF_SECTION_HEADER         = 40
win32con.PE_SECTION_NAME_SIZE                = 0x08
win32con.PE_SECTION_VOFFSET_OFFSET           = 0x0c
win32con.PE_SECTION_SIZE_OF_RAW_DATA_OFFSET  = 0x10
win32con.PE_RVA_OFFSET                       = 0x78
win32con.PE_RVA_SIZE                         = 0x7c
win32con.RVA_NUM_PROCS_OFFSET                = 0x14
win32con.RVA_NUM_PROCS_NAMES_OFFSET          = 0x18
win32con.RVA_PROCS_ADDRESSES_OFFSET          = 0x1c
win32con.RVA_PROCS_NAMES_OFFSET              = 0x20
win32con.RVA_PROCS_ORDINALS_OFFSET           = 0x24

from ctypes import *

def ErrorIfZero(handle):
    if handle == 0:
        raise WinError()
    else:
        return handle

def NtStatusCheck(ntStatus):
    if ntStatus < 0 or ntStatus > 0x80000000:
        raise WinError()
    else:
        return ntStatus

TRUE = c_char(  chr( int( True  ) ) )
FALSE = c_char( chr( int( False ) ) )
void_NULL = c_void_p( win32con.NULL )
pchar_NULL = c_char_p( win32con.NULL )

from .Win64Structs import *

OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [
    c_uint,     # DWORD dwDesiredAccess
    c_int,      # BOOL bInheritHandle
    c_uint ]    # DWORD dwProcessId
OpenProcess.restype = ErrorIfZero

GetCurrentProcess = windll.kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = ErrorIfZero

OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [
    c_void_p,   # HANDLE ProcessHandle
    c_uint,     # DWORD DesiredAccess
    c_void_p ]  # PHANDLE TokenHandle
OpenProcessToken.restype = ErrorIfZero

AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [
    c_void_p,   # HANDLE TokenHandle
    c_int,      # BOOL DisableAllPrivileges
    c_void_p,   # PTOKEN_PRIVILEGES NewState
    c_uint,     # DWORD BufferLength
    c_void_p,   # PTOKEN_PRIVILEGES PreviousState
    c_void_p ]  # PDWORD ReturnLength
AdjustTokenPrivileges.restype = ErrorIfZero

EnumProcessModules = windll.psapi.EnumProcessModules
EnumProcessModules.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # HMODULE* lphModule
    c_uint,     # DWORD cb
    c_void_p ]  # LPDWORD lpcbNeeded
EnumProcessModules.restype = ErrorIfZero

EnumProcesses = windll.psapi.EnumProcesses
EnumProcesses.argtypes = [
    c_void_p,
    c_uint,
    c_void_p]
EnumProcesses.restype = ErrorIfZero

GetModuleBaseName = windll.psapi.GetModuleBaseNameA
GetModuleBaseName.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # HMODULE hModule
    c_void_p,   # LPTSTR lpBaseName
    c_uint ]    # DWORD nSize
GetModuleBaseName.restype = ErrorIfZero

GetModuleInformation = windll.psapi.GetModuleInformation
GetModuleInformation.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # HMODULE hModule
    c_void_p,   # LPMODULEINFO lpmodinfo
    c_uint ]    # DWORD cb
GetModuleInformation.restype = ErrorIfZero

GetProcessHeaps = windll.kernel32.GetProcessHeaps
GetProcessHeaps.argtypes = [
    c_uint,     # DWORD NumberOfHeaps
    c_void_p ]  # PHANDLE ProcessHeaps
GetProcessHeaps.restype = c_uint

HeapQueryInformation = windll.kernel32.HeapQueryInformation
HeapQueryInformation.argtypes = [
    c_void_p,   # HANDLE HeapHandle
    c_int,      # HEAP_INFORMATION_CLASS HeapInformationClass
    c_void_p,   # PVOID HeapInformation
    c_longlong, # SIZE_T HeapInformationLength
    c_void_p ]  # PSIZE_T ReturnLength
HeapQueryInformation.restype = ErrorIfZero

HeapWalk = windll.kernel32.HeapWalk
HeapWalk.argtypes = [
    c_void_p,   # HANDLE hHeap
    c_void_p ]  # LPPROCESS_HEAP_ENTRY lpEntry
HeapWalk.restype = c_uint

LookupPrivilegeValue = windll.advapi32.LookupPrivilegeValueA
LookupPrivilegeValue.argtypes = [
    c_char_p,   # LPCTSTR lpSystemName
    c_char_p,   # LPCTSTR lpName
    c_void_p ]  # PLUID lpLuid
LookupPrivilegeValue.restype = ErrorIfZero

ReadProcessMemory = windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    c_int,      # hProcess // handle to the process
    c_void_p,     # lpBaseAddress // base of memory area
    c_void_p,   # lpBuffer // data buffer
    c_uint,     # nSize // number of bytes to read
    c_void_p]   # lpNumberOfBytesWritten // number of bytes write
ReadProcessMemory.restype = c_uint

WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    c_int,      # hProcess // handle to the process
    c_uint,     # lpBaseAddress // base of memory area
    c_void_p,   # lpBuffer // data buffer
    c_uint,     # nSize // number of bytes to read
    c_void_p]   # lpNumberOfBytesRead // number of bytes read
WriteProcessMemory.restype = ErrorIfZero

QueryWorkingSet = windll.psapi.QueryWorkingSet
QueryWorkingSet.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # PVOID pv
    c_uint]     # DWORD cb
QueryWorkingSet.restype = ErrorIfZero

VirtualProtectEx = windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [
    c_void_p,   # HANDLE
    c_void_p,   # Address
    c_uint,     # SIZE
    c_uint,     # Protection
    c_void_p ]  # Old protection
VirtualProtectEx.restype = ErrorIfZero

VirtualQueryEx = windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    c_int,      # HANDLE hProces
    c_void_p,   # LPCVOID lpAddress
    c_void_p,   # PMEMORY_BASIC_INFORMATION lpBuffer
    c_ulong ] # SIZE_T dwLength
VirtualQueryEx.restype = ErrorIfZero

# VirtualAllocEx
VirtualAllocEx = windll.kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [
        c_uint,         # HANDLE hProcess
        c_void_p,       # LPVOID lpAddress
        c_uint,         # SIZE_T dwSize
        c_uint,         # DWORD flAllocationType
        c_uint ]        # DWORD flProtect
VirtualAllocEx.restype = ErrorIfZero

# WriteProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
        c_uint,         # HANDLE hProcess
        c_uint,         # LPVOID lpBaseAddress
        c_char_p,       # LPCVOID lpBuffer
        c_uint,         # SIZE_T nSize
        c_void_p ]      # SIZE_T* lpNumberOfBytesWritten
WriteProcessMemory.restype = ErrorIfZero

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [ c_int ]
CloseHandle.restype = ErrorIfZero

class MODULEINFO( Structure ):
    _fields_ = [
            ('lpBaseOfDll',     c_void_p),
            ('SizeOfImage',     c_uint),
            ('EntryPoint',      c_void_p) ]

class LUID( Structure ):
    _fields_ = [
            ('LowPart',         c_uint),
            ('HighPart',        c_uint)]

class TOKEN_PRIVILEGES( Structure ):
    _fields_ = [
            ('PrivilegeCount',  c_uint),
            ('Luid',            LUID),
            ('Attributes',      c_uint) ]
    
class PROCESS_HEAP_ENTRY( Structure ):
    _fields_ = [
            ('lpData',          c_void_p),
            ('cbData',          c_uint),
            ('cbOverhead',      c_byte),
            ('iRegionIndex',    c_byte),
            ('wFalgs',          c_uint16),
            ('more_info1',      c_uint),
            ('more_info2',      c_uint),
            ('more_info3',      c_uint),
            ('more_info4',      c_uint) ]

class UNICODE_STRING( Structure ):
    _fields_ = [
            ('Length',          c_uint16),
            ('MaximumLength',   c_uint16),
            ('Buffer',          c_wchar_p) ]

class OBJECT_BASIC_INFORMATION( Structure ):
    _fields_ = [
            ('Attributes',          c_uint),
            ('DesiredAccess',       c_uint),
            ('HandleCount',         c_uint),
            ('ReferenceCount',      c_uint),
            ('PagedPoolUsage',      c_uint),
            ('NonPagedPoolUsage',   c_uint),
            ('Reserved',            c_uint * 3),
            ('NameInformationLength',   c_uint),
            ('TypeInformationLength',   c_uint),
            ('SecurityDescriptorLength',    c_uint),
            ('CreationTime',        c_ulonglong) ]

class OBJECT_NAME_INFORMATION( Structure ):
    _fields_ = [
            ('UnicodeStr',      UNICODE_STRING) ]
            

class GENERIC_MAPPING( Structure ):
    _fields_ = [
            ('GenericRead',     c_uint),
            ('GenericWrite',    c_uint),
            ('GenericExecute',  c_uint),
            ('GenericAll',      c_uint)]

class OBJECT_TYPE_INFROMATION( Structure ):
    _fields_ = [
            ('TypeName',                UNICODE_STRING),
            ('TotalNumberOfHandles',    c_uint),
            ('TotalNumberOfObjects',    c_uint),
            ('Unused1',                 c_uint16*8),
            ('HighWaterNumberOfHandles',    c_uint),
            ('HighWaterNumberOfObjects',    c_uint),
            ('Unused2',                 c_uint16*8),
            ('InvalidAttributes',       c_uint),
            ('GenericMapping',          GENERIC_MAPPING),
            ('ValidAttributes',         c_uint),
            ('SecurityRequired',        c_int),
            ('MaintainHandleCount',     c_int),
            ('MaintainTypeList',        c_uint16),
            ('PoolType',                c_uint),
            ('DefaultPagedPoolCharge',  c_uint),
            ('DefaultNonPagedPoolCharge',   c_uint) ]

DuplicateHandle = windll.kernel32.DuplicateHandle
DuplicateHandle.argtypes = [
    c_int,      #  __in   HANDLE hSourceProcessHandle,
    c_int,      #  __in   HANDLE hSourceHandle,
    c_int,      #  __in   HANDLE hTargetProcessHandle,
    c_void_p,   #  __out  LPHANDLE lpTargetHandle,
    c_uint,     #  __in   DWORD dwDesiredAccess,
    c_int,      #  __in   BOOL bInheritHandle,
    c_uint ]    #  __in   DWORD dwOptions
DuplicateHandle.restype = ErrorIfZero


NtQueryObject = windll.ntdll.NtQueryObject
NtQueryObject.argtypes = [
    c_void_p,   #  __in_opt   HANDLE Handle,
    c_uint,     #  __in       OBJECT_INFORMATION_CLASS ObjectInformationClass,
    c_void_p,   #  __out_opt  PVOID ObjectInformation,
    c_uint,     #  __in       ULONG ObjectInformationLength,
    c_void_p ]  #  __out_opt  PULONG ReturnLength
NtQueryObject.restype = c_uint

NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [
    c_void_p,   #  __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    c_void_p,   #  __inout    PVOID SystemInformation,
    c_uint,     #  __in       ULONG SystemInformationLength,
    c_void_p ]  #  __out_opt  PULONG ReturnLength
NtQuerySystemInformation.restype = c_uint
    

GetModuleFileNameEx = windll.psapi.GetModuleFileNameExA
GetModuleFileNameEx.argtypes = [
        c_int,      #  __in      HANDLE hProcess,
        c_uint,     #  __in_opt  HMODULE hModule,
        c_void_p,   #  __out     LPTSTR lpFilename,
        c_uint ]    #  __in      DWORD nSize
GetModuleFileNameEx.restype = ErrorIfZero

class SYSTEM_HANDLE( Structure ):
    _fields_ = [
            ('uIdProcess',  c_uint),
            ('ObjectType',  c_byte),
            ('Flags',       c_byte),
            ('Handle',      c_uint16),
            ('object',      c_void_p),
            ('GrantedAccess',   c_uint) ]

class SYSTEM_HANDLE_INFORMATION( Structure ):
    _fields_ = [
            ('uCount',      c_uint),
            ('Handle',      SYSTEM_HANDLE) ]

class SYSTEM_HANDLE_INFORMATION( Structure ):
    _fields_ = [
            ('uCount',          c_uint),
            ('SystemHandle',    SYSTEM_HANDLE) ]

SYMOPT_DEBUG = 0x80000000

SymGetOptions = windll.dbghelp.SymGetOptions
SymGetOptions.argtypes = []
SymGetOptions.restype = c_uint

SymSetOptions = windll.dbghelp.SymSetOptions
SymSetOptions.argtypes = [ c_uint ]
SymSetOptions.restype = c_uint

SymInitialize = windll.dbghelp.SymInitialize
SymInitialize.argtypes = [
        c_uint,     # HANDLE hProcess
        c_char_p,   # PCTSTR UserSearchPath
        c_uint ]    # BOOL fInvadeProcess
SymInitialize.restype = ErrorIfZero

SymLoadModule64 = windll.dbghelp.SymLoadModule64
SymLoadModule64.argtypes = [
        c_uint,     # HANDLE hProcess
        c_uint,     # HANDLE hFile
        c_char_p,   # PCSTR ImageNmae
        c_char_p,   # PCSTR ModuleName
        c_uint64,   # DWORD64 BaseOfDll
        c_uint ]    # SizeOfDll
SymLoadModule64.restype = c_uint64

class SYMBOL_INFO( Structure ):
    _fields_ = [
            ('SuzeOfStruct',        c_uint),
            ('TypeIndex',           c_uint),
            ('reserved1',           c_uint64),
            ('reserved2',           c_uint64),
            ('Index',               c_uint),
            ('Size',                c_uint),
            ('ModBase',             c_uint64),
            ('Flags',               c_uint),
            ('Value',               c_uint64),
            ('Address',             c_uint64),
            ('Register',            c_uint),
            ('Scope',               c_uint),
            ('Tag',                 c_uint),
            ('NameLen',             c_uint),
            ('MaxNameLen',          c_uint),
            ('Name',                ARRAY(c_char, 0x1000)) ]
                
SYM_ENUMERATESYMBOLS_CALLBACK = WINFUNCTYPE( c_uint, POINTER(SYMBOL_INFO), c_uint, c_void_p )

SymEnumSymbols = windll.dbghelp.SymEnumSymbols
SymEnumSymbols.argtypes = [
        c_uint,     # HANDLE hProcess
        c_uint64,   # ULONG64 BaseOfDll
        c_char_p,   # PCTSTR Mask
        SYM_ENUMERATESYMBOLS_CALLBACK, # PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback
        c_void_p ]  # PVOID UserContext
SymEnumSymbols.restype = ErrorIfZero

SymUnloadModule64 = windll.dbghelp.SymUnloadModule64
SymUnloadModule64.argtypes = [
        c_uint,     # HANDLE hProcess
        c_uint64 ]  # DWORD64 BaseOfDll
SymUnloadModule64.restype = ErrorIfZero

SymCleanup = windll.dbghelp.SymCleanup
SymCleanup.argtypes = [ c_uint ] # HANDLE hProcess
SymCleanup.restype = ErrorIfZero

class STARTUPINFO( Structure ):
    _fields_ = [
        ('cb',          c_uint),
        ('lpReserved',      c_char_p),
        ('lpDesktop',       c_char_p),
        ('lpTitle',     c_char_p),
        ('dwX',         c_uint),
        ('dwY',         c_uint),
        ('dwXSize',     c_uint),
        ('dwYSize',     c_uint),
        ('dwXCountChars',   c_uint),
        ('dwYCountChars',   c_uint),
        ('dwFillAttribute', c_uint),
        ('dwFlags',     c_uint),
        ('wShowWindow',     c_ushort),
        ('cbReserved2',     c_ushort),
        ('lpReserved2',     c_void_p),
        ('hStdInput',       c_int),
        ('hStdOutput',      c_int),
        ('hStdError',       c_int) ]

class PROCESS_INFORMATION( Structure ):
    _fields_ = [
        ('hProcess',    c_int),
        ('hThread', c_int),
        ('dwProcessId', c_uint),
        ('dwThreadId',  c_uint) ]
        
CreateProcess = windll.kernel32.CreateProcessA
CreateProcess.argtypes = [
    c_char_p,   # lpApplicationName // name of executable module
    c_char_p,   # lpCommandLine     // command line string
    c_void_p,   # lpProcessAttributes   // SD
    c_void_p,   # lpThreadAttributes    // SD
    c_char,     # bInheritHandles   // handle inheritance option
    c_uint,     # dwCreationFlags   // creation flags
    c_void_p,   # lpEnvironment     // new environment block
    c_char_p,   # lpCurrentDirectory    // current directory name
    c_void_p,   # lpStartupInfo     // startup information
    c_void_p ]  # lpProcessInformation  // process information
CreateProcess.restype = ErrorIfZero

ResumeThread = windll.kernel32.ResumeThread
ResumeThread.argtypes = [c_uint]
ResumeThread.restype = c_uint

CreateRemoteThread = windll.kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [
        c_uint,         # HANDLE hProcess
        c_void_p,       # LPSECURITY_ATTRIBUTES lpThreadAttributes
        c_uint,         # SIZE_T dwStackSize
        c_void_p,       # LPTHREAD_START_ROUTINE lpStartAddress
        c_void_p,       # LPVOID lpParameter
        c_uint,         # DWORD dwCreationFlags
        c_void_p ]      # LPDWORD lpThreadId        
CreateRemoteThread.restype = ErrorIfZero

class EXCEPTION_RECORD( Structure ):
    _fields_ = [
        ('ExceptionCode',           c_int ),
        ('ExceptionFlags',          c_uint ),
        ('pExceptionRecord',        c_void_p ),
        ('ExceptionAddress',        c_void_p ),
        ('NumberParameters',        c_uint ),
        ('ExceptionInformation',    ARRAY( c_void_p, 15 )) ]

class EXCEPTION_DEBUG_INFO( Structure ):
    _fields_ = [
        ('ExceptionRecord', EXCEPTION_RECORD),
        ('dwFirstChance',   c_uint ) ]

class CREATE_THREAD_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hThread',             c_int ),
        ('lpThreadLocalBase',   c_uint ),
        ('lpStartAddress',      c_uint ) ]
    
class CREATE_PROCESS_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hFile',                   c_int ),
        ('hProcess',                c_int ),
        ('hThread',                 c_int ),
        ('lpBaseOfImage',           c_uint ),
        ('dwDebugInfoFileOffset',   c_uint ),
        ('nDebugInfoSize',          c_uint ),
        ('lpThreadLocalBase',       c_uint ),
        ('lpStartAddress',          c_uint ),
        ('lpImageName',             c_uint ),
        ('fUnicode',                c_ushort ) ]
        
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [("BaseAddress", c_void_p),
                ("AllocationBase", c_void_p),
                ("AllocationProtect", c_uint),
                ("RegionSize", c_long),
                ("State", c_uint),
                ("Protect", c_uint),
                ("Type", c_uint),]

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("Length", c_uint),
                ("SecDescriptor", c_void_p),
                ("InheritHandle", c_uint)]
    
class EXIT_THREAD_DEBUG_INFO( Structure ):
    _fields_ = [
        ('dwExitCode',  c_uint ) ]

class EXIT_PROCESS_DEBUG_INFO( Structure ):
    _fields_ = [
        ('dwExitCode',  c_uint ) ]

class LOAD_DLL_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hFile',                   c_uint),
        ('lpBaseOfDll',             c_uint),
        ('dwDebugInfoFileOffset',   c_uint),
        ('nDebugInfoSize',          c_uint),
        ('lpImageName',             c_uint),
        ('fUnicode',                c_ushort)]

class UNLOAD_DLL_DEBUG_INFO( Structure ):
    _fields_ = [('lpBaseOfDll', c_void_p)]

class OUTPUT_DEBUG_STRING_INFO( Structure ):
    _fields_ = [
        ('lpDebugStringData',   c_char_p),
        ('fUnicode',            c_ushort),
        ('nDebugStringLength',  c_ushort) ]
        

class DEBUG_EVENT_u( Union ):
    _fields_ = [
        ('Exception',           EXCEPTION_DEBUG_INFO),
        ('CreateThread',        CREATE_THREAD_DEBUG_INFO),
        ('CreateProcessInfo',   CREATE_PROCESS_DEBUG_INFO),
        ('ExitThread',          EXIT_THREAD_DEBUG_INFO),
        ('ExitProcess',         EXIT_PROCESS_DEBUG_INFO),
        ('LoadDll',             LOAD_DLL_DEBUG_INFO),
        ('UnloadDll',           UNLOAD_DLL_DEBUG_INFO),
        ('DebugString',         OUTPUT_DEBUG_STRING_INFO) ]
    
    
class DEBUG_EVENT( Structure ):
    _fields_ = [
        ('dwDebugEventCode',    c_int),
        ('dwProcessId',         c_uint),
        ('dwThreadId',          c_uint),
        ('u',                   DEBUG_EVENT_u) ]

ContinueDebugEvent = windll.kernel32.ContinueDebugEvent
ContinueDebugEvent.argtypes = [
    c_uint,     # dwProcessId // process to continue
    c_uint,     # dwThreadId // thread to continue
    c_uint ]    # dwContinueStatus // continuation status
ContinueDebugEvent.restype = ErrorIfZero

WaitForDebugEvent = windll.kernel32.WaitForDebugEvent
WaitForDebugEvent.argtypes = [
    c_void_p,   # lpDebugEvent // debug event information
    c_uint]     # dwMilliseconds // time-out value
WaitForDebugEvent.restype = ErrorIfZero

GetThreadContext = windll.kernel32.GetThreadContext
GetThreadContext.argtypes = [
    c_int,      # hThread // handle to thread with context
    c_void_p]   # lpContext // context structure
GetThreadContext.restype = ErrorIfZero

SetThreadContext = windll.kernel32.SetThreadContext
SetThreadContext.argtypes = [
    c_int,      # hThread // handle to thread
    c_void_p]   # *lpContext // context structure
SetThreadContext.restype = ErrorIfZero

class FLOATING_SAVE_AREA( Structure ):
    _fields_ = [
        ('ControlWord',     c_uint),
        ('StatusWord',      c_uint),
        ('TagWord',     c_uint),
        ('ErrorOffset',     c_uint),
        ('ErrorSelector',   c_uint),
        ('DataOffset',      c_uint),
        ('DataSelector',    c_uint),
        ('RegisterArea',    ARRAY( c_char, 80 )),
        ('Cr0NpxState',     c_uint) ]

class CONTEXT( Structure ):
    _fields_ = [
###     ('data',    ARRAY(c_uint, 1000) )]
        ('ContextFlags',    c_uint),
    ('dr0',         c_uint),
    ('dr1',         c_uint),
    ('dr2',         c_uint),
    ('dr3',         c_uint),
    ('dr6',         c_uint),
    ('dr7',         c_uint),
    ('floatsave',   FLOATING_SAVE_AREA),
    ('seggs',       c_uint),
    ('segfs',       c_uint),
    ('seges',       c_uint),
    ('segds',       c_uint),
    ('edi',         c_uint),
    ('esi',         c_uint),
    ('ebx',         c_uint),
    ('edx',         c_uint),
    ('ecx',         c_uint),
    ('eax',         c_uint),
    ('ebp',         c_uint),
    ('eip',         c_uint),
    ('segcs',       c_uint),
    ('eflags',      c_uint),
    ('esp',         c_uint),
    ('segss',       c_uint),
    ('ExtendedRegisters',   ARRAY( c_char, 512 )) ]

FlushInstructionCache = windll.kernel32.FlushInstructionCache
FlushInstructionCache.argtypes = [
    c_int,      # hProcess // handle to the process
    c_void_p,   # lpBaseAddress // A pointer to the base of the region to be flushed
    c_uint ]    # dwSize // The size of the region to be flushed
FlushInstructionCache.restype = ErrorIfZero

GetModuleHandle = windll.kernel32.GetModuleHandleA
GetModuleHandle.argtypes = [
    c_char_p ]  # lpModuleName // module name
GetModuleHandle.restype = ErrorIfZero

LoadLibrary = windll.kernel32.LoadLibraryA
LoadLibrary.argtypes = [ c_char_p ]
LoadLibrary.restype = ErrorIfZero

GetProcAddress = windll.kernel32.GetProcAddress
GetProcAddress.argtypes = [
    c_int,      # hModule // handle to DLL module
    c_char_p ]  # lpProcName // function name
GetProcAddress.restype = ErrorIfZero

DebugActiveProcess = windll.kernel32.DebugActiveProcess
DebugActiveProcess.argtypes = [
    c_uint ]    # dwProcessId // process to be debugged
DebugActiveProcess.restype = ErrorIfZero

DebugActiveProcessStop = windll.kernel32.DebugActiveProcessStop
DebugActiveProcessStop.argtypes = [
        c_uint ]    # dwProcessId // process to stop debugging
DebugActiveProcessStop.restyp = ErrorIfZero

