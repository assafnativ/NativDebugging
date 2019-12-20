from builtins import bytes

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
win32con.PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
win32con.PROCESS_ALL_ACCESS             = 0x1f0fff
win32con.MEM_COMMIT                     = 0x1000
win32con.MEM_FREE                       = 0x10000
win32con.MEM_RESERVE                    = 0x2000
win32con.PAGE_NOACCESS                  = 0x01
win32con.PAGE_EXECUTE_READWRITE         = 0x40
win32con.PAGE_GUARD                     = 0x100
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
win32con.CONTEXT_AMD64                  = 0x00100000
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
win32con.CREATE_DEFAULT_ERROR_MODE      = 0x04000000
win32con.PAGE_READWRITE                 = 4
win32con.IMAGE_FILE_DLL                 = 0x2000
win32con.IMAGE_NT_OPTIONAL_HDR32_MAGIC  = 0x10b
win32con.IMAGE_NT_OPTIONAL_HDR64_MAGIC  = 0x20b
STATUS_WAIT_0                    = 0
STATUS_ABANDONED_WAIT_0          = 128
STATUS_USER_APC                  = 192
STATUS_TIMEOUT                   = 258
STATUS_PENDING                   = 259
STATUS_SEGMENT_NOTIFICATION      = 0x40000005
STATUS_GUARD_PAGE_VIOLATION      = 0x80000001
STATUS_DATATYPE_MISALIGNMENT     = 0x80000002
STATUS_BREAKPOINT                = 0x80000003
STATUS_SINGLE_STEP               = 0x80000004
STATUS_ACCESS_VIOLATION          = 0xc0000005
STATUS_IN_PAGE_ERROR             = 0xc0000006
STATUS_INVALID_HANDLE            = 0xc0000008
STATUS_NO_MEMORY                 = 0xc0000017
STATUS_ILLEGAL_INSTRUCTION       = 0xc000001d
STATUS_NONCONTINUABLE_EXCEPTION  = 0xc0000025
STATUS_INVALID_DISPOSITION       = 0xc0000026
STATUS_ARRAY_BOUNDS_EXCEEDED     = 0xc000008c
STATUS_FLOAT_DENORMAL_OPERAND    = 0xc000008d
STATUS_FLOAT_DIVIDE_BY_ZERO      = 0xc000008e
STATUS_FLOAT_INEXACT_RESULT      = 0xc000008f
STATUS_FLOAT_INVALID_OPERATION   = 0xc0000090
STATUS_FLOAT_OVERFLOW            = 0xc0000091
STATUS_FLOAT_STACK_CHECK         = 0xc0000092
STATUS_FLOAT_UNDERFLOW           = 0xc0000093
STATUS_INTEGER_DIVIDE_BY_ZERO    = 0xc0000094
STATUS_INTEGER_OVERFLOW          = 0xc0000095
STATUS_PRIVILEGED_INSTRUCTION    = 0xc0000096
STATUS_STACK_OVERFLOW            = 0xc00000fd
STATUS_CONTROL_C_EXIT            = 0xc000013a
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
from ctypes import create_string_buffer, create_unicode_buffer, byref, cast, addressof, sizeof, windll, WinDLL, Structure, Union, WINFUNCTYPE
from ctypes import wintypes as wt
from ctypes import wstring_at, string_at
from ctypes import ARRAY as c_ARRAY
from ctypes import POINTER as c_POINTER
from ctypes import WinError

def ErrorIfZero(res, func, args):
    if not res:
        raise WinError()
    return res

def ErrorIfNotZero(res, func, args):
    if res != 0:
        raise WinError(res)
    return res

def HResultErrorCheck(res, func, args):
    if 0 < res:
        raise RuntimeError(res)
    return res

def ErrorIfMinous1(res, func, args):
    if res == -1 or res == 0xffffffff:
        raise WinError()
    return res

def NtStatusCheck(ntStatus, func, args):
    if ntStatus < 0 or ntStatus > 0x80000000:
        raise WinError()
    return ntStatus

def FakeRrturnFalse(*arg):
    return False

TRUE = c_char(bytes([int(True)]))
FALSE = c_char(bytes([int(False)]))
void_NULL = c_void_p( win32con.NULL )
pchar_NULL = c_char_p( win32con.NULL )
_IN_     = 1
_OUT_    = 2
_DEFAULT_ZERO_ = 4
_IN_OUT_ = _IN_ | _OUT_

ntdll    = windll.ntdll
kernel32 = windll.kernel32
user32   = windll.user32
ole32    = windll.ole32
dbghelp  = windll.dbghelp
psapi    = windll.psapi
advapi32 = windll.advapi32

IsWow64Process_proto = WINFUNCTYPE(wt.BOOL, wt.HANDLE, c_POINTER(wt.BOOL))
if hasattr(kernel32, 'IsWow64Process'):
    IsWow64Process = IsWow64Process_proto(
            ('IsWow64Process', kernel32),
            ((_IN_, 'hProcess', None), (_OUT_, 'Wow64Process')))
    def IsWow64Process_errCheck(res, func, args):
        if not res:
            raise WinError()
        return args[1].value
    IsWow64Process.errcheck = IsWow64Process_errCheck
else:
    IsWow64Process = FakeRrturnFalse

OpenProcess_proto = WINFUNCTYPE(wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
OpenProcess = OpenProcess_proto(
        ('OpenProcess', kernel32),
        ((_IN_, 'dwDesiredAccess'), (_IN_, 'bInheritHandle', False), (_IN_, 'dwProcessId')))
OpenProcess.errcheck = ErrorIfZero

GetCurrentProcess_proto = WINFUNCTYPE(wt.HANDLE)
GetCurrentProcess = GetCurrentProcess_proto(('GetCurrentProcess', kernel32))
GetCurrentProcess.errcheck = ErrorIfZero

GetCurrentThread_proto = WINFUNCTYPE(wt.HANDLE)
GetCurrentThread = GetCurrentThread_proto(('GetCurrentThread', kernel32))
GetCurrentThread.errcheck = ErrorIfZero

OpenProcessToken_proto = WINFUNCTYPE(wt.BOOL, wt.HANDLE, wt.DWORD, c_POINTER(wt.HANDLE))
OpenProcessToken = OpenProcessToken_proto(
        ('OpenProcessToken', advapi32),
        ((_IN_, 'ProcessHandle', None), (_IN_, 'DesiredAccess'), (_OUT_, 'TokenHandle')))
def OpenProcessToken_errcheck(res, func, args):
    if not res:
        raise WinError()
    return args[2].value
OpenProcessToken.errcheck = OpenProcessToken_errcheck

class LUID( Structure ):
    _fields_ = [
            ('LowPart',         c_uint32),
            ('HighPart',        c_uint32)]
class TOKEN_PRIVILEGES( Structure ):
    _fields_ = [
            ('PrivilegeCount',  c_uint32),
            ('Luid',            LUID),
            ('Attributes',      c_uint32) ]

AdjustTokenPrivileges_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        wt.BOOL,
        c_POINTER(TOKEN_PRIVILEGES),
        wt.DWORD,
        c_POINTER(TOKEN_PRIVILEGES),
        c_POINTER(wt.DWORD))
AdjustTokenPrivileges = AdjustTokenPrivileges_proto(
        ('AdjustTokenPrivileges', advapi32), (
            (_IN_, 'TokenHandle'),
            (_IN_, 'DisableAllPrivileges'),
            (_IN_OUT_, 'NewState'),
            (_IN_, 'BufferLength'),
            (_IN_OUT_, 'PreviousState'),
            (_IN_OUT_, 'ReturnLength')))
AdjustTokenPrivileges.errcheck = ErrorIfZero

EnumProcessModules_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p,
        wt.DWORD,
        c_POINTER(wt.DWORD))
if hasattr(kernel32, 'K32EnumProcessModules'):
    EnumProcessModules = EnumProcessModules_proto(('K32EnumProcessModules', kernel32), (
                (_IN_, 'hProcess'),
                (_IN_, 'lphModule'),
                (_IN_, 'cb'),
                (_IN_OUT_, 'lpcbNeeded')))
else:
    EnumProcessModules = EnumProcessModules_proto(('EnumProcessModules', psapi), (
                (_IN_, 'hProcess'),
                (_IN_, 'lphModule'),
                (_IN_, 'cb'),
                (_IN_OUT_, 'lpcbNeeded')))
EnumProcessModules.errcheck = ErrorIfZero

EnumProcessModulesEx_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_POINTER(wt.HMODULE),
        wt.DWORD,
        c_POINTER(wt.DWORD),
        wt.DWORD)
if hasattr(kernel32, 'K32EnumProcessModules'):
    EnumProcessModulesEx = EnumProcessModulesEx_proto(
            ('K32EnumProcessModulesEx', kernel32), (
                (_IN_, 'hProcess'),
                (_IN_OUT_, 'lphModule'),
                (_IN_, 'cb'),
                (_IN_OUT_, 'lpcbNeeded'),
                (_IN_, 'dwFilterFlag')))
else:
    EnumProcessModulesEx = EnumProcessModulesEx_proto(
            ('EnumProcessModulesEx', psapi), (
                (_IN_, 'hProcess'),
                (_IN_OUT_, 'lphModule'),
                (_IN_, 'cb'),
                (_IN_OUT_, 'lpcbNeeded'),
                (_IN_, 'dwFilterFlag')))
EnumProcessModulesEx.errcheck = ErrorIfZero

EnumProcesses_proto = WINFUNCTYPE(
        wt.BOOL,
        c_void_p,
        wt.DWORD,
        c_POINTER(wt.DWORD))
EnumProcesses = EnumProcesses_proto(('EnumProcesses', psapi), (
            (_IN_, 'lpidProcess'),
            (_IN_, 'cb'),
            (_IN_OUT_, 'lpcbNeeded')))
EnumProcesses.errcheck = ErrorIfZero

GetProcessImageFileName_proto = WINFUNCTYPE(
        wt.DWORD,
        wt.HANDLE,
        wt.LPWSTR,
        wt.DWORD)
GetProcessImageFileName = GetProcessImageFileName_proto(('GetProcessImageFileNameW', psapi), (
        (_IN_, 'hProcess'),
        (_IN_, 'lpImageFileName'),
        (_IN_, 'nSize')))
def GetProcessImageFileName_errcheck(res, func, args):
    if not res:
        raise WinError()
    return args[1].value[:res]
GetProcessImageFileName.errcheck = GetProcessImageFileName_errcheck

GetModuleBaseName_proto = WINFUNCTYPE(
        wt.DWORD,
        wt.HANDLE,
        wt.HMODULE,
        wt.LPWSTR,
        wt.DWORD)
GetModuleBaseName = GetModuleBaseName_proto(('GetModuleBaseNameW', psapi), (
        (_IN_, 'hProcess'),
        (_IN_, 'hModule'),
        (_IN_, 'lpBaseName'),
        (_IN_, 'nSize')))
def GetModuleBaseName_errcheck(res, func, args):
    if not res:
        raise WinError()
    return args[2].value
GetModuleBaseName.errcheck = GetModuleBaseName_errcheck

GetModuleFileName_proto = WINFUNCTYPE(
        wt.DWORD,
        wt.HMODULE,
        wt.LPWSTR,
        wt.DWORD)
GetModuleFileName = GetModuleFileName_proto(('GetModuleFileNameW', kernel32), (
        (_IN_, 'hModule'),
        (_IN_, 'lpFilename'),
        (_IN_, 'nSize')))
GetModuleFileName.errcheck = GetModuleBaseName_errcheck
GetModuleFileNameEx_proto = WINFUNCTYPE(
        wt.DWORD,
        wt.DWORD,
        wt.HMODULE,
        wt.LPWSTR,
        wt.DWORD)
GetModuleFileNameEx = GetModuleFileNameEx_proto(('GetModuleFileNameExW', psapi), (
                (_IN_, 'hProcess'),
                (_IN_, 'hModule'),
                (_IN_, 'lpFilename'),
                (_IN_, 'nSize')))
GetModuleFileNameEx.errcheck = GetModuleBaseName_errcheck

class MODULEINFO( Structure ):
    _fields_ = [
            ('lpBaseOfDll',     c_void_p),
            ('SizeOfImage',     c_uint32),
            ('EntryPoint',      c_void_p) ]
GetModuleInformation_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        wt.HMODULE,
        c_POINTER(MODULEINFO),
        wt.DWORD)
GetModuleInformation = GetModuleInformation_proto(('GetModuleInformation', psapi), (
        (_IN_, 'hProcess'),
        (_IN_, 'hModule'),
        (_IN_, 'lpmodinfo'),
        (_IN_, 'cb')))
GetModuleInformation.errcheck = ErrorIfZero

GetProcessHeaps_proto = WINFUNCTYPE(
        wt.DWORD,
        wt.DWORD,
        c_POINTER(wt.HANDLE))
GetProcessHeaps = GetProcessHeaps_proto(('GetProcessHeaps', kernel32), (
        (_IN_, 'NumberOfHeaps'),
        (_IN_, 'ProcessHeaps')))
GetProcessHeaps.errcheck = ErrorIfZero

HeapQueryInformation_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        wt.DWORD,
        c_void_p,
        c_size_t,
        c_POINTER(c_size_t))
HeapQueryInformation = HeapQueryInformation_proto(('HeapQueryInformation', kernel32), (
        (_IN_, 'HeapHandle'),
        (_IN_, 'HeapInformationClass'),
        (_IN_, 'HeapInformation'),
        (_IN_, 'HeapInformationLength'),
        (_IN_, 'ReturnLength')))
HeapQueryInformation.errcheck = ErrorIfZero

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
HeapWalk_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_POINTER(PROCESS_HEAP_ENTRY))
HeapWalk = HeapWalk_proto(('HeapWalk', kernel32), (
        (_IN_, 'hHeap'),
        (_IN_, 'lpEntry')))
HeapWalk.errcheck = ErrorIfZero

LookupPrivilegeValue_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.LPCWSTR,
        wt.LPCWSTR,
        c_POINTER(LUID))
LookupPrivilegeValue = LookupPrivilegeValue_proto(('LookupPrivilegeValueW', advapi32), (
            (_IN_,  'lpSystemName'),
            (_IN_,  'lpName'),
            (_IN_,  'lpLuid')))
LookupPrivilegeValue.errcheck = ErrorIfZero

ReadProcessMemory_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p,
        c_void_p,
        c_size_t,
        c_POINTER(c_size_t))
ReadProcessMemory = ReadProcessMemory_proto(('ReadProcessMemory', kernel32), (
        (_IN_, 'hProcess'),
        (_IN_, 'lpBaseAddress'),
        (_IN_, 'lpBuffer'),
        (_IN_, 'nSize'),
        (_IN_, 'lpNumberOfBytesWritten')))
ReadProcessMemory.errcheck = ErrorIfZero

WriteProcessMemory_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p,
        c_void_p,
        c_size_t,
        c_POINTER(c_size_t))
WriteProcessMemory = WriteProcessMemory_proto(('WriteProcessMemory', kernel32), (
        (_IN_, 'hProcess'),
        (_IN_, 'lpBaseAddress'),
        (_IN_, 'lpBuffer'),
        (_IN_, 'nSize'),
        (_IN_, 'lpNumberOfBytesRead')))
WriteProcessMemory.errcheck = ErrorIfZero

QueryWorkingSet_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p,
        wt.DWORD)
QueryWorkingSet = QueryWorkingSet_proto(('QueryWorkingSet', psapi), (
            (_IN_,  'hProcess'),
            (_IN_,  'pv'),
            (_IN_,  'cb')))
QueryWorkingSet.errcheck = ErrorIfZero

VirtualProtectEx_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p,
        c_size_t,
        wt.DWORD,
        c_POINTER(wt.DWORD))
VirtualProtectEx = VirtualProtectEx_proto(('VirtualProtectEx', kernel32), (
        (_IN_,  'hProcess'),
        (_IN_,  'lpAddress'),
        (_IN_,  'dwSize'),
        (_IN_,  'flNewProtect'),
        (_IN_,  'lpfOldProtect')))
VirtualProtectEx.errcheck = ErrorIfZero

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [("BaseAddress",         c_void_p),
                ("AllocationBase",      c_void_p),
                ("AllocationProtect",   c_uint32),
                ("RegionSize",          c_size_t),
                ("State",               c_uint32),
                ("Protect",             c_uint32),
                ("Type",                c_uint32)]
VirtualQueryEx_proto = WINFUNCTYPE(
        c_size_t,
        wt.HANDLE,
        c_void_p,
        c_POINTER(MEMORY_BASIC_INFORMATION),
        c_size_t)
VirtualQueryEx = VirtualQueryEx_proto(('VirtualQueryEx', kernel32), (
            (_IN_,  'hProces'),
            (_IN_,  'lpAddress'),
            (_IN_,  'lpBuffer'),
            (_IN_,  'dwLength')))
VirtualQueryEx.errcheck = ErrorIfZero

VirtualAllocEx_proto = WINFUNCTYPE(
        c_void_p,
        wt.HANDLE,
        c_void_p,
        c_size_t,
        wt.DWORD,
        wt.DWORD)
VirtualAllocEx = VirtualAllocEx_proto(('VirtualAllocEx', kernel32), (
            (_IN_,  'hProcess'),
            (_IN_,  'lpAddress'),
            (_IN_,  'dwSize'),
            (_IN_,  'flAllocationType'),
            (_IN_,  'flProtect')))
def VirtualAllocEx_errcheck(res, func, args):
    if not res.value:
        raise WinError
    return res
VirtualAllocEx.errcheck = VirtualAllocEx_errcheck

CloseHandle_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE)
CloseHandle = CloseHandle_proto(('CloseHandle', kernel32), ((_IN_, 'hObject'),))
CloseHandle.errcheck = ErrorIfZero

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

DuplicateHandle_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE, wt.HANDLE, wt.HANDLE,
        c_POINTER(wt.HANDLE),
        wt.DWORD,
        wt.BOOL,
        wt.DWORD)
DuplicateHandle = DuplicateHandle_proto(('DuplicateHandle', kernel32), (
            (_IN_, 'hSourceProcessHandle'),
            (_IN_, 'hSourceHandle'),
            (_IN_, 'hTargetProcessHandle'),
            (_IN_, 'lpTargetHandle'),
            (_IN_, 'dwDesiredAccess'),
            (_IN_, 'bInheritHandle'),
            (_IN_, 'dwOption')))
DuplicateHandle.errcheck = ErrorIfZero

NtQueryObject_proto = WINFUNCTYPE(
        c_uint32,
        wt.HANDLE,
        c_uint32,
        c_void_p,
        c_uint32,
        c_POINTER(c_uint32))
NtQueryObject = NtQueryObject_proto(('NtQueryObject', ntdll), (
            (_IN_, 'Handle'),
            (_IN_, 'ObjectInformationClass'),
            (_IN_, 'ObjectInformation'),
            (_IN_, 'ObjectInformationLength'),
            (_IN_, 'ReturnLengt')))
NtQueryObject.errcheck = NtStatusCheck

NtQuerySystemInformation_proto = WINFUNCTYPE(
        c_uint32,
        c_uint32,
        c_void_p,
        c_uint32,
        c_POINTER(c_uint32))
NtQuerySystemInformation = NtQuerySystemInformation_proto(('NtQuerySystemInformation', ntdll), (
            (_IN_, 'SystemInformationClass'),
            (_IN_, 'SystemInformation'),
            (_IN_, 'SystemInformationLength'),
            (_IN_, 'ReturnLengt')))
NtQuerySystemInformation.errcheck = NtStatusCheck

class PROCESS_BASIC_INFORMATION( Structure ):
    _fields_ = [
            ('ExitStatus',      c_void_p),
            ('PebBaseAddress',  c_void_p),
            ('AffinityMask',    c_void_p),
            ('BasePriority',    c_void_p),
            ('UniqueProcessId', c_void_p),
            ('InheritedFromUniqueProcessId', c_void_p)]

NtQueryInformationProcess_proto = WINFUNCTYPE(
        c_uint32,
        wt.HANDLE,
        c_void_p,
        c_void_p,
        c_uint32,
        c_POINTER(c_uint32))
NtQueryInformationProcess = NtQueryInformationProcess_proto(('NtQueryInformationProcess', ntdll), (
                (_IN_, 'ProcessHandl'),
                (_IN_, 'ProcessInformationClas'),
                (_IN_, 'ProcessInformatio'),
                (_IN_, 'ProcessInformationLengt'),
                (_IN_, 'ReturnLengt')))
NtQueryInformationProcess.errcheck = NtStatusCheck

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

SymGetOptions_proto = WINFUNCTYPE(wt.DWORD)
SymGetOptions = SymGetOptions_proto(('SymGetOptions', dbghelp), ())
SymSetOptions_proto = WINFUNCTYPE(wt.DWORD, wt.DWORD)
SymSetOptions = SymSetOptions_proto(('SymSetOptions', dbghelp), ((_IN_, 'SymOptions'),))

SymInitialize_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        wt.LPCWSTR,
        wt.BOOL)
SymInitialize = SymInitialize_proto(('SymInitialize', dbghelp), (
            (_IN_,  'hProcess'),
            (_IN_,  'UserSearchPath'),
            (_IN_,  'fInvadeProcess')))
SymInitialize.errcheck = ErrorIfZero

SYM_FIND_FILE_IN_PATH_CALLBACK = WINFUNCTYPE(
                                        wt.LPCWSTR, # PCTSTR fileName
                                        c_void_p) # PVOID context
SymFindFileInPath_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        wt.LPCWSTR, wt.LPCWSTR,
        c_void_p,
        wt.DWORD, wt.DWORD, wt.DWORD,
        wt.LPWSTR,
        c_void_p,
        c_void_p)
SymFindFileInPath = SymFindFileInPath_proto(('SymFindFileInPathW', dbghelp), (
            (_IN_,  'hProcess'),
            (_IN_,  'SearchPath'),
            (_IN_,  'FileName'),
            (_IN_,  'id'),
            (_IN_,  'two'),
            (_IN_,  'three'),
            (_IN_,  'flags'),
            (_IN_,  'FilePath'),
            (_IN_,  'callback'), # SYM_FIND_FILE_IN_PATH_CALLBACK
            (_IN_,  'context')))
SymFindFileInPath.errcheck = ErrorIfZero

win32con.SSRVOPT_DWORD      = 0x02 # The id parameter is a DWORD.
win32con.SSRVOPT_DWORDPTR   = 0x04 # The id parameter is a pointer to a DWORD.
win32con.SSRVOPT_GUIDPTR    = 0x08 # The id parameter is a pointer to a GUID.

SymLoadModuleEx_proto = WINFUNCTYPE(
        c_uint64,
        wt.HANDLE, wt.HANDLE,
        wt.LPCWSTR, wt.LPCWSTR,
        c_uint64,
        wt.DWORD,
        c_void_p,
        wt.DWORD)
SymLoadModuleEx = SymLoadModuleEx_proto(('SymLoadModuleExW', dbghelp), (
            (_IN_,  'hProcess'),
            (_IN_,  'hFile'),
            (_IN_,  'ImageNmae'),
            (_IN_,  'ModuleName'),
            (_IN_,  'BaseOfDll'),
            (_IN_,  'DllSize'),
            (_IN_,  'Data', None),
            (_IN_,  'Flags', 0)))
SymLoadModuleEx.errcheck = ErrorIfZero

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

SymEnumSymbols_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_uint64,
        wt.LPCWSTR,
        c_void_p, # SYM_ENUMERATESYMBOLS_CALLBACK
        c_void_p)
SymEnumSymbols = SymEnumSymbols_proto(('SymEnumSymbols', dbghelp), (
            (_IN_,  'hProcess'),
            (_IN_,  'BaseOfDll'),
            (_IN_,  'Mask'),
            (_IN_,  'EnumSymbolsCallback'), # SYM_ENUMERATESYMBOLS_CALLBACK
            (_IN_,  'UserContext')))
SymEnumSymbols.errcheck = ErrorIfZero

SymUnloadModule64_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_uint64)
SymUnloadModule64 = SymUnloadModule64_proto(('SymUnloadModule64', dbghelp), (
            (_IN_,  'hProcess'),
            (_IN_,  'BaseOfDll')))
SymUnloadModule64.errcheck = ErrorIfZero

SymCleanup_proto = WINFUNCTYPE(wt.BOOL, wt.HANDLE)
SymCleanup = SymCleanup_proto(('SymCleanup', dbghelp), ((_IN_, 'hProcess'),))
SymCleanup.errcheck = ErrorIfZero

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
        ('hProcess',    c_void_p),
        ('hThread',     c_void_p),
        ('dwProcessId', c_uint32),
        ('dwThreadId',  c_uint32) ]

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("Length", c_uint32),
                ("SecDescriptor", c_void_p),
                ("InheritHandle", c_uint32)]

CreateProcess_proto = WINFUNCTYPE(
        wt.BOOL,
        c_void_p,
        c_void_p,
        c_POINTER(SECURITY_ATTRIBUTES),
        c_POINTER(SECURITY_ATTRIBUTES),
        wt.BOOL,
        wt.DWORD,
        c_void_p,
        c_void_p,
        c_POINTER(STARTUPINFO),
        c_POINTER(PROCESS_INFORMATION))
CreateProcess = CreateProcess_proto(('CreateProcessW', kernel32), (
            (_IN_, 'lpApplicationName'),
            (_IN_, 'lpCommandLine'),
            (_IN_, 'lpProcessAttributes'),
            (_IN_, 'lpThreadAttributes'),
            (_IN_, 'bInheritHandles'),
            (_IN_, 'dwCreationFlags'),
            (_IN_, 'lpEnvironment'),
            (_IN_, 'lpCurrentDirectory'),
            (_IN_, 'lpStartupInfo'),
            (_IN_, 'lpProcessInformation')))
CreateProcess.errcheck = ErrorIfZero

ResumeThread_proot = WINFUNCTYPE(
        wt.DWORD, wt.HANDLE)
ResumeThread = ResumeThread_proot(('ResumeThread', kernel32), ((_IN_, 'hThread'),))
ResumeThread.errcheck = ErrorIfMinous1

CreateRemoteThread_proto = WINFUNCTYPE(
        wt.HANDLE,
        wt.HANDLE,
        c_POINTER(SECURITY_ATTRIBUTES),
        c_size_t,
        c_void_p,
        c_void_p,
        wt.DWORD,
        c_POINTER(wt.DWORD))
CreateRemoteThread = CreateRemoteThread_proto(('CreateRemoteThread', kernel32), (
            (_IN_,  'hProcess'),
            (_IN_,  'lpThreadAttributes'),
            (_IN_,  'dwStackSize'),
            (_IN_,  'lpStartAddress'),
            (_IN_,  'lpParameter'),
            (_IN_,  'dwCreationFlags'),
            (_IN_,  'lpThreadId')))
CreateRemoteThread.errcheck = ErrorIfZero

class EXCEPTION_RECORD( Structure ):
    _fields_ = [
        ('ExceptionCode',           c_uint32 ),
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
        ('hThread',             c_void_p ),
        ('lpThreadLocalBase',   c_void_p ),
        ('lpStartAddress',      c_void_p ) ]

class CREATE_PROCESS_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hFile',                   c_void_p ),
        ('hProcess',                c_void_p ),
        ('hThread',                 c_void_p ),
        ('lpBaseOfImage',           c_void_p ),
        ('dwDebugInfoFileOffset',   c_uint32 ),
        ('nDebugInfoSize',          c_uint32 ),
        ('lpThreadLocalBase',       c_void_p ),
        ('lpStartAddress',          c_void_p ),
        ('lpImageName',             c_void_p ),
        ('fUnicode',                c_uint16 ) ]

class EXIT_THREAD_DEBUG_INFO( Structure ):
    _fields_ = [
        ('dwExitCode',  c_uint32 ) ]

class EXIT_PROCESS_DEBUG_INFO( Structure ):
    _fields_ = [
        ('dwExitCode',  c_uint32 ) ]

class LOAD_DLL_DEBUG_INFO( Structure ):
    _fields_ = [
        ('hFile',                   c_void_p),
        ('lpBaseOfDll',             c_void_p),
        ('dwDebugInfoFileOffset',   c_uint32),
        ('nDebugInfoSize',          c_uint32),
        ('lpImageName',             c_void_p),
        ('fUnicode',                c_uint16)]

class UNLOAD_DLL_DEBUG_INFO( Structure ):
    _fields_ = [('lpBaseOfDll', c_void_p)]

class OUTPUT_DEBUG_STRING_INFO( Structure ):
    _fields_ = [
        ('lpDebugStringData',   c_void_p),
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

ContinueDebugEvent_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.DWORD, wt.DWORD, wt.DWORD)
ContinueDebugEvent = ContinueDebugEvent_proto(('ContinueDebugEvent', kernel32), (
            (_IN_, 'dwProcessId'),
            (_IN_, 'dwThreadId'),
            (_IN_, 'dwContinueStatus')))
ContinueDebugEvent.errcheck = ErrorIfZero

WaitForDebugEvent_proto = WINFUNCTYPE(
        wt.BOOL,
        c_POINTER(DEBUG_EVENT),
        wt.DWORD)
WaitForDebugEvent = WaitForDebugEvent_proto(('WaitForDebugEvent', kernel32), (
            (_IN_, 'lpDebugEvent'),
            (_IN_, 'dwMilliseconds')))
WaitForDebugEvent.errcheck = ErrorIfZero

GetThreadContext_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p)
GetThreadContext = GetThreadContext_proto(('GetThreadContext', kernel32), (
            (_IN_, 'hThread'),
            (_IN_, 'lpContext')))
GetThreadContext.errcheck = ErrorIfZero

SetThreadContext_proot = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p)
SetThreadContext = SetThreadContext_proot(('SetThreadContext', kernel32), (
            (_IN_, 'hThread'),
            (_IN_, '*lpContext')))
SetThreadContext.errcheck = ErrorIfZero

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

class CONTEXT_x86( Structure ):
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

class CONTEXT_x86_64( Structure ):
    _fields_ = [
        ('P1Home',  c_uint64),
        ('P2Home',  c_uint64),
        ('P3Home',  c_uint64),
        ('P4Home',  c_uint64),
        ('P5Home',  c_uint64),
        ('P6Home',  c_uint64),
        ('ContextFlags',    c_uint32),
        ('MxCsr',           c_uint32),
        ('segcs',   c_uint16),
        ('segds',   c_uint16),
        ('seges',   c_uint16),
        ('segfs',   c_uint16),
        ('seggs',   c_uint16),
        ('segss',   c_uint16),
        ('eflags',  c_uint32),
        ('dr0',     c_uint64),
        ('dr1',     c_uint64),
        ('dr2',     c_uint64),
        ('dr3',     c_uint64),
        ('dr6',     c_uint64),
        ('dr7',     c_uint64),
        ('rax',     c_uint64),
        ('rcx',     c_uint64),
        ('rdx',     c_uint64),
        ('rbx',     c_uint64),
        ('rsp',     c_uint64),
        ('rbp',     c_uint64),
        ('rsi',     c_uint64),
        ('rdi',     c_uint64),
        ('r8',      c_uint64),
        ('r9',      c_uint64),
        ('r10',     c_uint64),
        ('r11',     c_uint64),
        ('r12',     c_uint64),
        ('r13',     c_uint64),
        ('r14',     c_uint64),
        ('r15',     c_uint64),
        ('rip',     c_uint64),
        ('FloatingPointData',   c_ARRAY(c_uint64, 80)),
        ('VectorRegister',      c_ARRAY(c_uint64, 52)),
        ('VectorControl',       c_uint64),
        ('DebugControl',        c_uint64),
        ('LastBranchToRip',     c_uint64),
        ('LastBranchFromRip',   c_uint64),
        ('LastExceptionToRip',  c_uint64),
        ('LastExceptionFromRip',c_uint64)]

FlushInstructionCache_proto = WINFUNCTYPE(
        wt.BOOL,
        wt.HANDLE,
        c_void_p,
        c_size_t)
FlushInstructionCache = FlushInstructionCache_proto(('FlushInstructionCache', kernel32), (
            (_IN_, 'hProcess'),
            (_IN_, 'lpBaseAddress'),
            (_IN_, 'dwSize')))
FlushInstructionCache.errcheck = ErrorIfZero

GetModuleHandle_proto = WINFUNCTYPE(wt.HMODULE, wt.LPCWSTR)
GetModuleHandle = GetModuleHandle_proto(('GetModuleHandleW', kernel32), ((_IN_, 'lpModuleName'),))
GetModuleHandle.errcheck = ErrorIfZero

LoadLibrary_proto = WINFUNCTYPE(wt.HMODULE, wt.LPCWSTR)
LoadLibrary = LoadLibrary_proto(('LoadLibraryW', kernel32), ((_IN_, 'lpLibFileName'),))
LoadLibrary.errcheck = ErrorIfZero

GetProcAddress_proto = WINFUNCTYPE(c_void_p, wt.HMODULE, wt.LPCSTR)
GetProcAddress = GetProcAddress_proto(('GetProcAddress', kernel32), (
            (_IN_, 'hModule'),
            (_IN_, 'lpProcName')))
GetProcAddress.errcheck = ErrorIfZero

DebugActiveProcess_proto = WINFUNCTYPE(wt.BOOL, wt.DWORD)
DebugActiveProcess = DebugActiveProcess_proto(('DebugActiveProcess', kernel32), ((_IN_, 'dwProcessId'),))
DebugActiveProcess.errcheck = ErrorIfZero

DebugActiveProcessStop = DebugActiveProcess_proto(('DebugActiveProcessStop', kernel32), ((_IN_, 'dwProcessId'),))
DebugActiveProcessStop.errcheck = ErrorIfZero

GetProcessId_proto = WINFUNCTYPE(wt.DWORD, wt.HANDLE)
GetProcessId = GetProcessId_proto(('GetProcessId', kernel32), ((_IN_, 'Process'),))
GetProcessId.errcheck = ErrorIfZero

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
GetSystemInfo_proto = WINFUNCTYPE(c_uint32, c_POINTER(SYSTEM_INFO))
GetSystemInfo = GetSystemInfo_proto(('GetSystemInfo', kernel32), ((_IN_, 'lpSystemInfo'),))

OpenFileMapping_proto = WINFUNCTYPE(wt.HANDLE, wt.DWORD, wt.BOOL, wt.LPCSTR)
OpenFileMapping = OpenFileMapping_proto(('OpenFileMappingA', kernel32), (
            (_IN_, 'dwDesiredAccess'),
            (_IN_, 'bInheritHandle'),
            (_IN_, 'lpName')))
OpenFileMapping.errcheck = ErrorIfZero

MapViewOfFile_proto = WINFUNCTYPE(
            c_void_p,
            wt.HANDLE,
            wt.DWORD, wt.DWORD, wt.DWORD,
            c_size_t)
MapViewOfFile = MapViewOfFile_proto(('MapViewOfFile', kernel32), (
            (_IN_,  'hFileMappingObject'),
            (_IN_,  'dwDesiredAccess'),
            (_IN_,  'dwFileOffsetHigh'),
            (_IN_,  'dwFileOffsetLow'),
            (_IN_,  'dwNumberOfBytesToMap')))
MapViewOfFile.errcheck = ErrorIfZero

GetFinalPathNameByHandle_proto = WINFUNCTYPE(
        wt.DWORD,
        wt.HANDLE,
        wt.LPWSTR,
        wt.DWORD,
        wt.DWORD)
GetFinalPathNameByHandle = GetFinalPathNameByHandle_proto(('GetFinalPathNameByHandleW', kernel32), (
            (_IN_,  'hFile'),
            (_IN_,  'lpszFilePath'),
            (_IN_,  'cchFilePath'),
            (_IN_,  'dwFlags')))
GetFinalPathNameByHandle.errcheck = ErrorIfZero

CoInitialize_proto = WINFUNCTYPE(wt.LONG, c_void_p)
CoInitialize = CoInitialize_proto(('CoInitialize', ole32), ((_IN_, 'pvReserved', None),))
CoInitialize.errcheck = HResultErrorCheck

CoCreateInstance_proto = WINFUNCTYPE(
        wt.LONG,
        c_void_p,
        c_void_p,
        wt.DWORD,
        c_void_p,
        c_void_p)
CoCreateInstance = CoCreateInstance_proto(('CoCreateInstance', ole32), (
        (_IN_, 'rclsid'),
        (_IN_, 'pUnkOuter'),
        (_IN_, 'dwClsContext'),
        (_IN_, 'riid'),
        (_IN_, 'ppv')))
CoCreateInstance.errcheck = HResultErrorCheck

SymTagEnum = [
    'SymTagNull', # 0
    'SymTagExe', # 1
    'SymTagCompiland', # 2
    'SymTagCompilandDetails', # 3
    'SymTagCompilandEnv', # 4
    'SymTagFunction', # 5
    'SymTagBlock', # 6
    'SymTagData', # 7
    'SymTagAnnotation', # 8
    'SymTagLabel', # 9
    'SymTagPublicSymbol', # 10
    'SymTagUDT', # 11
    'SymTagEnum', # 12
    'SymTagFunctionType', # 13
    'SymTagPointerType', # 14
    'SymTagArrayType', # 15
    'SymTagBaseType', # 16
    'SymTagTypedef', # 17
    'SymTagBaseClass', # 18
    'SymTagFriend', # 19
    'SymTagFunctionArgType', # 20
    'SymTagFuncDebugStart', # 21
    'SymTagFuncDebugEnd', # 22
    'SymTagUsingNamespace', # 23
    'SymTagVTableShape', # 24
    'SymTagVTable', # 25
    'SymTagCustom', # 26
    'SymTagThunk', # 27
    'SymTagCustomType', # 28
    'SymTagManagedType', # 29
    'SymTagDimension', # 30
    'SymTagCallSite', # 31
    'SymTagInlineSite', # 32
    'SymTagBaseInterface', # 33
    'SymTagVectorType', # 34
    'SymTagMatrixType', # 35
    'SymTagHLSLType', # 36
    'SymTagCaller', # 37
    'SymTagCallee', # 38
    'SymTagExport', # 39
    'SymTagHeapAllocationSite', # 40
    'SymTagCoffGroup', # 41
    'SymTagMax']
SymTagEnumTag = dict(zip(range(len(SymTagEnum)), SymTagEnum))
SymTagEnum = dict(zip(SymTagEnum, range(len(SymTagEnum))))

SymDataKind = [
    "Unknown",
    "Local",
    "Static Local",
    "Param",
    "Object Ptr",
    "File Static",
    "Global",
    "Member",
    "Static Member",
    "Constant" ]
SymDataKindTag = dict(zip(range(len(SymDataKind)), SymDataKind))
SymDataKind = dict(zip(SymDataKind, range(len(SymDataKind))))

SymBaseType = [
    "<NoType>", # 0
    "void",     # 1
    "char",     # 2
    "wchar_t",  # 3
    "signed char",  # 4
    "unsigned char",    # 5
    "int",      # 6
    "unsigned int", # 7
    "float",    # 8
    "<BCD>",    # 9
    "bool",     # 10
    "short",    # 11
    "unsigned short",   # 12
    "long",     # 13
    "unsigned long",    # 14
    "__int8",   # 15
    "__int16",  # 16
    "__int32",  # 17
    "__int64",  # 18
    "__int128", # 19
    "unsigned __int8",  # 20
    "unsigned __int16", # 21
    "unsigned __int32", # 22
    "unsigned __int64", # 23
    "unsigned __int128",    # 24
    "<currency>",   # 25
    "<date>",       # 26
    "VARIANT",      # 27
    "<complex>",    # 28
    "<bit>",        # 29
    "BSTR",         # 30
    "HRESULT"]      # 31
SymBaseTypeTag = dict(zip(range(len(SymBaseType)), SymBaseType))
SymBaseType = dict(zip(SymBaseType, range(len(SymBaseType))))

class WNDCLASSEX( Structure ):
    _fields_ = [
        ('cbSize',          c_uint32),
        ('style',           c_uint32),
        ('lpfnWndProc',     c_void_p),
        ('cbClsExtra',      c_int32),
        ('cbWndExtra',      c_int32),
        ('hInstance',       wt.HINSTANCE),
        ('hIcon',           c_void_p),
        ('hCursor',         c_void_p),
        ('hbrBackground',   c_void_p),
        ('lpszMenuName',    c_void_p),
        ('lpszClassName',   c_void_p),
        ('hIconSm',         c_void_p)]

