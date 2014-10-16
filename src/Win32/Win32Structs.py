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
win32con.PROCESS_CREATE_THREAD          = 0x0002
win32con.PROCESS_VM_OPERATION           = 0x0008
win32con.PROCESS_VM_READ                = 0x0010
win32con.PROCESS_VM_WRITE               = 0x0020
win32con.PROCESS_DUP_HANDLE             = 0x0040
win32con.PROCESS_SET_INFORMATION        = 0x0200
win32con.PROCESS_QUERY_INFORMATION      = 0x0400
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
win32con.LIST_MODULES_ALL                    = 3
win32con.PE_POINTER_OFFSET                   = 0x3c
win32con.PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET = 0x14
win32con.PE_SIZEOF_NT_HEADER                 = 0x18
win32con.PE_NUM_OF_SECTIONS_OFFSET           = 0x06
win32con.IMAGE_SIZEOF_SECTION_HEADER         = 40
win32con.PE_SECTION_NAME_SIZE                = 0x08
win32con.PE_SECTION_VOFFSET_OFFSET           = 0x0c
win32con.PE_SECTION_SIZE_OF_RAW_DATA_OFFSET  = 0x10
win32con.PE_OPTIONAL_HEADER_TYPE             = 0x18
win32con.PE_PLUS_EXTRA_BYTES                 = 0x10
win32con.PE_RVA_OFFSET                       = 0x78
win32con.PE_RVA_SIZE                         = 0x7c
win32con.RVA_NUM_PROCS_OFFSET                = 0x14
win32con.RVA_NUM_PROCS_NAMES_OFFSET          = 0x18
win32con.RVA_PROCS_ADDRESSES_OFFSET          = 0x1c
win32con.RVA_PROCS_NAMES_OFFSET              = 0x20
win32con.RVA_PROCS_ORDINALS_OFFSET           = 0x24
win32con.PE_MAGIC                            = 'PE'
win32con.EXE_MAGIC                           = 'MZ'
win32con.OPTIONAL_HEADER_MAGIC               = '\x0b\x01'
win32con.ROM_OPTIONAL_HEADER_MAGIC           = '\x07\x01'
win32con.SYSTEM_PROCESS_INFORMATION          = 5
win32con.PROCESS_BASIC_INFORMATION           = 0
win32con.FILE_MAP_READ                       = 4
win32con.FILE_MAP_WRITE                      = 2
win32con.FILE_MAP_EXECUTE                    = 0x20

from ctypes import c_char, c_wchar, c_int64, c_int32, c_int16, c_int8, c_uint64, c_uint32, c_uint16, c_uint8, c_size_t, c_void_p, c_char_p, c_wchar_p, c_buffer
from ctypes import create_string_buffer, byref, cast, addressof, sizeof, windll, Structure, Union, WINFUNCTYPE
from ctypes import ARRAY as c_ARRAY
from ctypes import POINTER as c_POINTER
from ctypes import WinError

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
from .Wow64Structs import *

OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [
    c_uint32,     # DWORD dwDesiredAccess
    c_int32,      # BOOL bInheritHandle
    c_uint32 ]    # DWORD dwProcessId
OpenProcess.restype = ErrorIfZero

GetCurrentProcess = windll.kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = ErrorIfZero

OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [
    c_void_p,   # HANDLE ProcessHandle
    c_uint32,     # DWORD DesiredAccess
    c_void_p ]  # PHANDLE TokenHandle
OpenProcessToken.restype = ErrorIfZero

AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [
    c_void_p,   # HANDLE TokenHandle
    c_int32,    # BOOL DisableAllPrivileges
    c_void_p,   # PTOKEN_PRIVILEGES NewState
    c_uint32,   # DWORD BufferLength
    c_void_p,   # PTOKEN_PRIVILEGES PreviousState
    c_void_p ]  # PDWORD ReturnLength
AdjustTokenPrivileges.restype = ErrorIfZero

EnumProcessModules = windll.psapi.EnumProcessModules
EnumProcessModules.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # HMODULE* lphModule
    c_uint32,   # DWORD cb
    c_void_p ]  # LPDWORD lpcbNeeded
EnumProcessModules.restype = c_uint32

try:
    EnumProcessModulesEx = windll.psapi.EnumProcessModulesEx
    EnumProcessModulesEx.argtypes = [
        c_void_p,   # HANDLE hProcess
        c_void_p,   # HMODULE* lphModule
        c_uint32,   # DWORD cb
        c_void_p,   # LPDWORD lpcbNeeded
        c_uint32]   # DWORD dwFilterFlag
    EnumProcessModulesEx.restype = ErrorIfZero
except AttributeError, e:
    EnumProcessModulesEx = None

EnumProcesses = windll.psapi.EnumProcesses
EnumProcesses.argtypes = [
    c_void_p,
    c_uint32,
    c_void_p]
EnumProcesses.restype = ErrorIfZero

GetModuleBaseName = windll.psapi.GetModuleBaseNameA
GetModuleBaseName.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # HMODULE hModule
    c_void_p,   # LPTSTR lpBaseName
    c_uint32 ]  # DWORD nSize
GetModuleBaseName.restype = ErrorIfZero

GetModuleFileName = windll.kernel32.GetModuleFileNameW
GetModuleFileName.argtypes = [
    c_void_p,   # HMODULE hModule
    c_void_p,   # LPTSTR lpFilename
    c_void_p ]  # DWORD nSize
GetModuleFileName.restype = ErrorIfZero

GetModuleInformation = windll.psapi.GetModuleInformation
GetModuleInformation.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # HMODULE hModule
    c_void_p,   # LPMODULEINFO lpmodinfo
    c_uint32 ]  # DWORD cb
GetModuleInformation.restype = ErrorIfZero

GetProcessHeaps = windll.kernel32.GetProcessHeaps
GetProcessHeaps.argtypes = [
    c_uint32,   # DWORD NumberOfHeaps
    c_void_p ]  # PHANDLE ProcessHeaps
GetProcessHeaps.restype = c_uint32

HeapQueryInformation = windll.kernel32.HeapQueryInformation
HeapQueryInformation.argtypes = [
    c_void_p,   # HANDLE HeapHandle
    c_int32,    # HEAP_INFORMATION_CLASS HeapInformationClass
    c_void_p,   # PVOID HeapInformation
    c_uint64,   # SIZE_T HeapInformationLength
    c_void_p ]  # PSIZE_T ReturnLength
HeapQueryInformation.restype = ErrorIfZero

HeapWalk = windll.kernel32.HeapWalk
HeapWalk.argtypes = [
    c_void_p,   # HANDLE hHeap
    c_void_p ]  # LPPROCESS_HEAP_ENTRY lpEntry
HeapWalk.restype = c_uint32

LookupPrivilegeValue = windll.advapi32.LookupPrivilegeValueA
LookupPrivilegeValue.argtypes = [
    c_char_p,   # LPCTSTR lpSystemName
    c_char_p,   # LPCTSTR lpName
    c_void_p ]  # PLUID lpLuid
LookupPrivilegeValue.restype = ErrorIfZero

ReadProcessMemory = windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    c_int32,    # hProcess // handle to the process
    c_void_p,   # lpBaseAddress // base of memory area
    c_void_p,   # lpBuffer // data buffer
    c_uint32,   # nSize // number of bytes to read
    c_void_p]   # lpNumberOfBytesWritten // number of bytes write
ReadProcessMemory.restype = c_uint32

WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    c_int32,      # hProcess // handle to the process
    c_uint32,     # lpBaseAddress // base of memory area
    c_void_p,     # lpBuffer // data buffer
    c_uint32,     # nSize // number of bytes to read
    c_void_p]     # lpNumberOfBytesRead // number of bytes read
WriteProcessMemory.restype = ErrorIfZero

QueryWorkingSet = windll.psapi.QueryWorkingSet
QueryWorkingSet.argtypes = [
    c_void_p,   # HANDLE hProcess
    c_void_p,   # PVOID pv
    c_uint32]   # DWORD cb
QueryWorkingSet.restype = c_uint32

VirtualProtectEx = windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [
    c_void_p,   # HANDLE
    c_void_p,   # Address
    c_uint32,   # SIZE
    c_uint32,   # Protection
    c_void_p ]  # Old protection
VirtualProtectEx.restype = ErrorIfZero

VirtualQueryEx = windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    c_int32,    # HANDLE hProces
    c_void_p,   # LPCVOID lpAddress
    c_void_p,   # PMEMORY_BASIC_INFORMATION lpBuffer
    c_uint32 ]  # SIZE_T dwLength
VirtualQueryEx.restype = ErrorIfZero

# VirtualAllocEx
VirtualAllocEx = windll.kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [
        c_uint32,       # HANDLE hProcess
        c_void_p,       # LPVOID lpAddress
        c_uint32,       # SIZE_T dwSize
        c_uint32,       # DWORD flAllocationType
        c_uint32 ]      # DWORD flProtect
VirtualAllocEx.restype = ErrorIfZero

# WriteProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
        c_uint32,       # HANDLE hProcess
        c_uint32,       # LPVOID lpBaseAddress
        c_char_p,       # LPCVOID lpBuffer
        c_uint32,       # SIZE_T nSize
        c_void_p ]      # SIZE_T* lpNumberOfBytesWritten
WriteProcessMemory.restype = ErrorIfZero

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [ c_int32 ]
CloseHandle.restype = ErrorIfZero

class MODULEINFO( Structure ):
    _fields_ = [
            ('lpBaseOfDll',     c_void_p),
            ('SizeOfImage',     c_uint32),
            ('EntryPoint',      c_void_p) ]

class LUID( Structure ):
    _fields_ = [
            ('LowPart',         c_uint32),
            ('HighPart',        c_uint32)]

class TOKEN_PRIVILEGES( Structure ):
    _fields_ = [
            ('PrivilegeCount',  c_uint32),
            ('Luid',            LUID),
            ('Attributes',      c_uint32) ]
    
class PROCESS_HEAP_ENTRY( Structure ):
    _fields_ = [
            ('lpData',          c_void_p),
            ('cbData',          c_uint32),
            ('cbOverhead',      c_uint8),
            ('iRegionIndex',    c_uint8),
            ('wFalgs',          c_uint16),
            ('more_info1',      c_uint32),
            ('more_info2',      c_uint32),
            ('more_info3',      c_uint32),
            ('more_info4',      c_uint32) ]

class UNICODE_STRING( Structure ):
    _fields_ = [
            ('Length',          c_uint16),
            ('MaximumLength',   c_uint16),
            ('Buffer',          c_wchar_p) ]

class OBJECT_BASIC_INFORMATION( Structure ):
    _fields_ = [
            ('Attributes',          c_uint32),
            ('DesiredAccess',       c_uint32),
            ('HandleCount',         c_uint32),
            ('ReferenceCount',      c_uint32),
            ('PagedPoolUsage',      c_uint32),
            ('NonPagedPoolUsage',   c_uint32),
            ('Reserved',            c_uint32 * 3),
            ('NameInformationLength',   c_uint32),
            ('TypeInformationLength',   c_uint32),
            ('SecurityDescriptorLength',    c_uint32),
            ('CreationTime',        c_uint64) ]

class OBJECT_NAME_INFORMATION( Structure ):
    _fields_ = [
            ('UnicodeStr',      UNICODE_STRING) ]
            

class GENERIC_MAPPING( Structure ):
    _fields_ = [
            ('GenericRead',     c_uint32),
            ('GenericWrite',    c_uint32),
            ('GenericExecute',  c_uint32),
            ('GenericAll',      c_uint32)]

class OBJECT_TYPE_INFROMATION( Structure ):
    _fields_ = [
            ('TypeName',                UNICODE_STRING),
            ('TotalNumberOfHandles',    c_uint32),
            ('TotalNumberOfObjects',    c_uint32),
            ('Unused1',                 c_uint16*8),
            ('HighWaterNumberOfHandles',    c_uint32),
            ('HighWaterNumberOfObjects',    c_uint32),
            ('Unused2',                 c_uint16*8),
            ('InvalidAttributes',       c_uint32),
            ('GenericMapping',          GENERIC_MAPPING),
            ('ValidAttributes',         c_uint32),
            ('SecurityRequired',        c_int32),
            ('MaintainHandleCount',     c_int32),
            ('MaintainTypeList',        c_uint16),
            ('PoolType',                c_uint32),
            ('DefaultPagedPoolCharge',  c_uint32),
            ('DefaultNonPagedPoolCharge',   c_uint32) ]


class SYSTEM_PROCESS_INFORMATION_DETAILD( Structure ):
    _fields_ = [
            ('NextEntryOffset',     c_uint32),
            ('NumberOfThreads',     c_uint32),
            ('SpareLi1',            c_uint64),
            ('SpareLi2',            c_uint64),
            ('SpareLi3',            c_uint64),
            ('CreateTime',          c_uint64),
            ('UserTime',            c_uint64),
            ('KernelTime',          c_uint64),
            ('ImageName',           UNICODE_STRING),
            ('BasePriority',        c_uint32),
            ('UniqueProcessId',     c_uint32),
            ('InheritedFromUniqueProcessId', c_uint32),
            ('HandleCount',         c_uint32),
            ('Reserved4',           c_uint32),
            ('Reserved5',           c_void_p*11),
            ('PeakPagefileUsage',   c_uint32),
            ('PrivatePageCount',    c_uint32),
            ('Reserved6',           c_uint64*6) ]

DuplicateHandle = windll.kernel32.DuplicateHandle
DuplicateHandle.argtypes = [
    c_int32,      #  __in   HANDLE hSourceProcessHandle,
    c_int32,      #  __in   HANDLE hSourceHandle,
    c_int32,      #  __in   HANDLE hTargetProcessHandle,
    c_void_p,     #  __out  LPHANDLE lpTargetHandle,
    c_uint32,     #  __in   DWORD dwDesiredAccess,
    c_int32,      #  __in   BOOL bInheritHandle,
    c_uint32 ]    #  __in   DWORD dwOptions
DuplicateHandle.restype = ErrorIfZero


NtQueryObject = windll.ntdll.NtQueryObject
NtQueryObject.argtypes = [
    c_void_p,   #  __in_opt   HANDLE Handle,
    c_uint32,   #  __in       OBJECT_INFORMATION_CLASS ObjectInformationClass,
    c_void_p,   #  __out_opt  PVOID ObjectInformation,
    c_uint32,   #  __in       ULONG ObjectInformationLength,
    c_void_p ]  #  __out_opt  PULONG ReturnLength
NtQueryObject.restype = c_uint32

NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [
    c_void_p,   #  __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    c_void_p,   #  __inout    PVOID SystemInformation,
    c_uint32,     #  __in       ULONG SystemInformationLength,
    c_void_p ]  #  __out_opt  PULONG ReturnLength
NtQuerySystemInformation.restype = c_uint32
    
class PROCESS_BASIC_INFORMATION( Structure ):
    _fields_ = [
            ('ExitStatus',      c_void_p),
            ('PebBaseAddress',  c_void_p),
            ('AffinityMask',    c_void_p),
            ('BasePriority',    c_void_p),
            ('UniqueProcessId', c_void_p),
            ('InheritedFromUniqueProcessId', c_void_p)]

NtQueryInformationProcess = windll.ntdll.NtQueryInformationProcess
NtQueryInformationProcess.argtypes = [
        c_uint32,   # _In_       HANDLE ProcessHandle
        c_void_p,   # _In_       PROCESSINFOCLASS ProcessInformationClass
        c_void_p,   # _Out_      PVOID ProcessInformation
        c_uint32,   # _In_       ULONG ProcessInformationLength
        c_void_p ]  # _Out_opt_  PULONG ReturnLength
NtQueryInformationProcess.restype = NtStatusCheck
    
GetModuleFileNameEx = windll.psapi.GetModuleFileNameExA
GetModuleFileNameEx.argtypes = [
        c_int32,      #  __in      HANDLE hProcess,
        c_uint32,     #  __in_opt  HMODULE hModule,
        c_void_p,   #  __out     LPTSTR lpFilename,
        c_uint32 ]    #  __in      DWORD nSize
GetModuleFileNameEx.restype = ErrorIfZero

class SYSTEM_HANDLE( Structure ):
    _fields_ = [
            ('uIdProcess',  c_uint32),
            ('ObjectType',  c_uint8),
            ('Flags',       c_uint8),
            ('Handle',      c_uint16),
            ('object',      c_void_p),
            ('GrantedAccess',   c_uint32) ]

class SYSTEM_HANDLE_INFORMATION( Structure ):
    _fields_ = [
            ('uCount',      c_uint32),
            ('Handle',      SYSTEM_HANDLE) ]

class SYSTEM_HANDLE_INFORMATION( Structure ):
    _fields_ = [
            ('uCount',          c_uint32),
            ('SystemHandle',    SYSTEM_HANDLE) ]

SYMOPT_DEBUG = 0x80000000

SymGetOptions = windll.dbghelp.SymGetOptions
SymGetOptions.argtypes = []
SymGetOptions.restype = c_uint32

SymSetOptions = windll.dbghelp.SymSetOptions
SymSetOptions.argtypes = [ c_uint32 ]
SymSetOptions.restype = c_uint32

SymInitialize = windll.dbghelp.SymInitialize
SymInitialize.argtypes = [
        c_uint32,     # HANDLE hProcess
        c_char_p,   # PCTSTR UserSearchPath
        c_uint32 ]    # BOOL fInvadeProcess
SymInitialize.restype = ErrorIfZero

SYM_FIND_FILE_IN_PATCH_CALLBACK = WINFUNCTYPE( 
                                        c_char_p, # PCTSTR fileName
                                        c_void_p) # PVOID context
SymFindFileInPath = windll.dbghelp.SymFindFileInPath
SymFindFileInPath.argtypes = [
        c_uint32,     # HANDLE hProcess
        c_char_p,   # PCTSTR SearchPath
        c_char_p,   # PCTSTR FileName
        c_void_p,   # PVOID id
        c_uint32,     # DWORD two
        c_uint32,     # DWORD three
        c_uint32,     # DWORD flags
        c_void_p,   # PTSTR FilePath
        c_void_p,   #SYM_FIND_FILE_IN_PATCH_CALLBACK,  # PFINDFILEINPATHCALLBACK callback
        c_void_p ]  # PVOID contex
SymFindFileInPath.restype = ErrorIfZero

win32con.SSRVOPT_DWORD      = 0x02 # The id parameter is a DWORD.
win32con.SSRVOPT_DWORDPTR   = 0x04 # The id parameter is a pointer to a DWORD.
win32con.SSRVOPT_GUIDPTR    = 0x08 # The id parameter is a pointer to a GUID.

SymLoadModule64 = windll.dbghelp.SymLoadModule64
SymLoadModule64.argtypes = [
        c_uint32,     # HANDLE hProcess
        c_uint32,     # HANDLE hFile
        c_char_p,   # PCSTR ImageNmae
        c_char_p,   # PCSTR ModuleName
        c_uint64,   # DWORD64 BaseOfDll
        c_uint32 ]    # SizeOfDll
SymLoadModule64.restype = c_uint64

class SYMBOL_INFO( Structure ):
    _fields_ = [
            ('SuzeOfStruct',        c_uint32),
            ('TypeIndex',           c_uint32),
            ('reserved1',           c_uint64),
            ('reserved2',           c_uint64),
            ('Index',               c_uint32),
            ('Size',                c_uint32),
            ('ModBase',             c_uint64),
            ('Flags',               c_uint32),
            ('Value',               c_uint64),
            ('Address',             c_uint64),
            ('Register',            c_uint32),
            ('Scope',               c_uint32),
            ('Tag',                 c_uint32),
            ('NameLen',             c_uint32),
            ('MaxNameLen',          c_uint32),
            ('Name',                c_ARRAY(c_char, 0x1000)) ]
                
SYM_ENUMERATESYMBOLS_CALLBACK = WINFUNCTYPE( c_uint32, c_POINTER(SYMBOL_INFO), c_uint32, c_void_p )

SymEnumSymbols = windll.dbghelp.SymEnumSymbols
SymEnumSymbols.argtypes = [
        c_uint32,     # HANDLE hProcess
        c_uint64,   # ULONG64 BaseOfDll
        c_char_p,   # PCTSTR Mask
        SYM_ENUMERATESYMBOLS_CALLBACK, # PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback
        c_void_p ]  # PVOID UserContext
SymEnumSymbols.restype = ErrorIfZero

SymUnloadModule64 = windll.dbghelp.SymUnloadModule64
SymUnloadModule64.argtypes = [
        c_uint32,     # HANDLE hProcess
        c_uint64 ]  # DWORD64 BaseOfDll
SymUnloadModule64.restype = ErrorIfZero

SymCleanup = windll.dbghelp.SymCleanup
SymCleanup.argtypes = [ c_uint32 ] # HANDLE hProcess
SymCleanup.restype = ErrorIfZero

class STARTUPINFO( Structure ):
    _fields_ = [
        ('cb',          c_uint32),
        ('lpReserved',      c_char_p),
        ('lpDesktop',       c_char_p),
        ('lpTitle',     c_char_p),
        ('dwX',         c_uint32),
        ('dwY',         c_uint32),
        ('dwXSize',     c_uint32),
        ('dwYSize',     c_uint32),
        ('dwXCountChars',   c_uint32),
        ('dwYCountChars',   c_uint32),
        ('dwFillAttribute', c_uint32),
        ('dwFlags',     c_uint32),
        ('wShowWindow',     c_uint16),
        ('cbReserved2',     c_uint16),
        ('lpReserved2',     c_void_p),
        ('hStdInput',       c_int32),
        ('hStdOutput',      c_int32),
        ('hStdError',       c_int32) ]

class PROCESS_INFORMATION( Structure ):
    _fields_ = [
        ('hProcess',    c_int32),
        ('hThread', c_int32),
        ('dwProcessId', c_uint32),
        ('dwThreadId',  c_uint32) ]
        
CreateProcess = windll.kernel32.CreateProcessA
CreateProcess.argtypes = [
    c_char_p,   # lpApplicationName // name of executable module
    c_char_p,   # lpCommandLine     // command line string
    c_void_p,   # lpProcessAttributes   // SD
    c_void_p,   # lpThreadAttributes    // SD
    c_char,     # bInheritHandles   // handle inheritance option
    c_uint32,   # dwCreationFlags   // creation flags
    c_void_p,   # lpEnvironment     // new environment block
    c_char_p,   # lpCurrentDirectory    // current directory name
    c_void_p,   # lpStartupInfo     // startup information
    c_void_p ]  # lpProcessInformation  // process information
CreateProcess.restype = ErrorIfZero

ResumeThread = windll.kernel32.ResumeThread
ResumeThread.argtypes = [c_uint32]
ResumeThread.restype = c_uint32

CreateRemoteThread = windll.kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [
        c_uint32,       # HANDLE hProcess
        c_void_p,       # LPSECURITY_ATTRIBUTES lpThreadAttributes
        c_uint32,       # SIZE_T dwStackSize
        c_void_p,       # LPTHREAD_START_ROUTINE lpStartAddress
        c_void_p,       # LPVOID lpParameter
        c_uint32,       # DWORD dwCreationFlags
        c_void_p ]      # LPDWORD lpThreadId        
CreateRemoteThread.restype = ErrorIfZero

class EXCEPTION_RECORD( Structure ):
    _fields_ = [
        ('ExceptionCode',           c_int32 ),
        ('ExceptionFlags',          c_uint32 ),
        ('pExceptionRecord',        c_void_p ),
        ('ExceptionAddress',        c_void_p ),
        ('NumberParameters',        c_uint32 ),
        ('ExceptionInformation',    c_ARRAY( c_void_p, 15 )) ]

class EXCEPTION_DEBUG_INFO( Structure ):
    _fields_ = [
        ('ExceptionRecord', EXCEPTION_RECORD),
        ('dwFirstChance',   c_uint32 ) ]

class CREATE_THREAD_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hThread',             c_int32 ),
        ('lpThreadLocalBase',   c_uint32 ),
        ('lpStartAddress',      c_uint32 ) ]
    
class CREATE_PROCESS_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hFile',                   c_int32 ),
        ('hProcess',                c_int32 ),
        ('hThread',                 c_int32 ),
        ('lpBaseOfImage',           c_uint32 ),
        ('dwDebugInfoFileOffset',   c_uint32 ),
        ('nDebugInfoSize',          c_uint32 ),
        ('lpThreadLocalBase',       c_uint32 ),
        ('lpStartAddress',          c_uint32 ),
        ('lpImageName',             c_uint32 ),
        ('fUnicode',                c_uint16 ) ]
        
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [("BaseAddress",         c_void_p),
                ("AllocationBase",      c_void_p),
                ("AllocationProtect",   c_uint32),
                ("RegionSize",          c_size_t),
                ("State",               c_uint32),
                ("Protect",             c_uint32),
                ("Type",                c_uint32)]

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("Length", c_uint32),
                ("SecDescriptor", c_void_p),
                ("InheritHandle", c_uint32)]
    
class EXIT_THREAD_DEBUG_INFO( Structure ):
    _fields_ = [
        ('dwExitCode',  c_uint32 ) ]

class EXIT_PROCESS_DEBUG_INFO( Structure ):
    _fields_ = [
        ('dwExitCode',  c_uint32 ) ]

class LOAD_DLL_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hFile',                   c_uint32),
        ('lpBaseOfDll',             c_uint32),
        ('dwDebugInfoFileOffset',   c_uint32),
        ('nDebugInfoSize',          c_uint32),
        ('lpImageName',             c_uint32),
        ('fUnicode',                c_uint16)]

class UNLOAD_DLL_DEBUG_INFO( Structure ):
    _fields_ = [('lpBaseOfDll', c_void_p)]

class OUTPUT_DEBUG_STRING_INFO( Structure ):
    _fields_ = [
        ('lpDebugStringData',   c_char_p),
        ('fUnicode',            c_uint16),
        ('nDebugStringLength',  c_uint16) ]
        

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
        ('dwDebugEventCode',    c_int32),
        ('dwProcessId',         c_uint32),
        ('dwThreadId',          c_uint32),
        ('u',                   DEBUG_EVENT_u) ]

ContinueDebugEvent = windll.kernel32.ContinueDebugEvent
ContinueDebugEvent.argtypes = [
    c_uint32,     # dwProcessId // process to continue
    c_uint32,     # dwThreadId // thread to continue
    c_uint32 ]    # dwContinueStatus // continuation status
ContinueDebugEvent.restype = ErrorIfZero

WaitForDebugEvent = windll.kernel32.WaitForDebugEvent
WaitForDebugEvent.argtypes = [
    c_void_p,   # lpDebugEvent // debug event information
    c_uint32]   # dwMilliseconds // time-out value
WaitForDebugEvent.restype = ErrorIfZero

GetThreadContext = windll.kernel32.GetThreadContext
GetThreadContext.argtypes = [
    c_int32,      # hThread // handle to thread with context
    c_void_p]   # lpContext // context structure
GetThreadContext.restype = ErrorIfZero

SetThreadContext = windll.kernel32.SetThreadContext
SetThreadContext.argtypes = [
    c_int32,      # hThread // handle to thread
    c_void_p]   # *lpContext // context structure
SetThreadContext.restype = ErrorIfZero

class FLOATING_SAVE_AREA( Structure ):
    _fields_ = [
        ('ControlWord',     c_uint32),
        ('StatusWord',      c_uint32),
        ('TagWord',     c_uint32),
        ('ErrorOffset',     c_uint32),
        ('ErrorSelector',   c_uint32),
        ('DataOffset',      c_uint32),
        ('DataSelector',    c_uint32),
        ('RegisterArea',    c_ARRAY( c_char, 80 )),
        ('Cr0NpxState',     c_uint32) ]

class CONTEXT( Structure ):
    _fields_ = [
###     ('data',    c_ARRAY(c_uint32, 1000) )]
        ('ContextFlags',    c_uint32),
    ('dr0',         c_uint32),
    ('dr1',         c_uint32),
    ('dr2',         c_uint32),
    ('dr3',         c_uint32),
    ('dr6',         c_uint32),
    ('dr7',         c_uint32),
    ('floatsave',   FLOATING_SAVE_AREA),
    ('seggs',       c_uint32),
    ('segfs',       c_uint32),
    ('seges',       c_uint32),
    ('segds',       c_uint32),
    ('edi',         c_uint32),
    ('esi',         c_uint32),
    ('ebx',         c_uint32),
    ('edx',         c_uint32),
    ('ecx',         c_uint32),
    ('eax',         c_uint32),
    ('ebp',         c_uint32),
    ('eip',         c_uint32),
    ('segcs',       c_uint32),
    ('eflags',      c_uint32),
    ('esp',         c_uint32),
    ('segss',       c_uint32),
    ('ExtendedRegisters',   c_ARRAY( c_char, 512 )) ]

FlushInstructionCache = windll.kernel32.FlushInstructionCache
FlushInstructionCache.argtypes = [
    c_int32,      # hProcess // handle to the process
    c_void_p,   # lpBaseAddress // A pointer to the base of the region to be flushed
    c_uint32 ]    # dwSize // The size of the region to be flushed
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
    c_int32,      # hModule // handle to DLL module
    c_char_p ]  # lpProcName // function name
GetProcAddress.restype = ErrorIfZero

DebugActiveProcess = windll.kernel32.DebugActiveProcess
DebugActiveProcess.argtypes = [
    c_uint32 ]    # dwProcessId // process to be debugged
DebugActiveProcess.restype = ErrorIfZero

DebugActiveProcessStop = windll.kernel32.DebugActiveProcessStop
DebugActiveProcessStop.argtypes = [
        c_uint32 ]    # dwProcessId // process to stop debugging
DebugActiveProcessStop.restyp = ErrorIfZero

GetProcessId = windll.kernel32.GetProcessId
GetProcessId.argtypes = [
        c_int32 ] # handle
GetProcessId.restype = ErrorIfZero

class SYSTEM_INFO( Structure ):
    _fields_ = [
            ('wProcessorArchitecture', c_uint16),
            ('wReserved',              c_uint16),
            ('dwPageSize',             c_uint32),
            ('lpMinimumApplicationAddress', c_void_p),
            ('lpMaximumApplicationAddress', c_void_p),
            ('dwActiveProcessorMask',       c_void_p),
            ('dwNumberOfProcessors',        c_uint32),
            ('dwProcessorType',             c_uint32),
            ('dwAllocationGranularity',     c_uint32),
            ('wProcessorLevel',             c_uint32),
            ('wProcessorRevision',          c_uint32) ]
GetSystemInfo = windll.kernel32.GetSystemInfo
GetSystemInfo.argtypes = [ c_void_p ] # LPSYSTEM_INFO
GetSystemInfo.restype = None

OpenFileMapping = windll.kernel32.OpenFileMappingA
OpenFileMapping.argtypes = [
          c_uint32, # dwDesiredAccess
          c_uint32, # bInheritHandle
          c_char_p ] # lpName
OpenFileMapping.restype = ErrorIfZero

MapViewOfFile = windll.kernel32.MapViewOfFile
MapViewOfFile.argtypes = [
          c_uint32, # HANDLE hFileMappingObject
          c_uint32, # DWORD dwDesiredAccess
          c_uint32, # DWORD dwFileOffsetHigh
          c_uint32, # DWORD dwFileOffsetLow
          c_uint32 ] # SIZE_T dwNumberOfBytesToMap
MapViewOfFile.restype = c_void_p

