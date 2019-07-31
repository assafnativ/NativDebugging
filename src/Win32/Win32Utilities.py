from ctypes import c_void_p, c_uint32, c_buffer, byref
from .Win32Structs import *

def adjustDebugPrivileges():
    privileges = TOKEN_PRIVILEGES()

    access_token = OpenProcessToken( GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES)
    LookupPrivilegeValue( None, "SeDebugPrivilege", byref(privileges.Luid) )
    privileges.PrivilegeCount = 1
    privileges.Attributes = 2
    AdjustTokenPrivileges(
            access_token,
            0,
            byref(privileges),
            0,
            None,
            None )
    CloseHandle( access_token )

def _enumProcessesOld():
    bufferSize = 0x1000
    while True:
        buf = create_string_buffer(bufferSize)
        returnLength = c_uint32(0)
        status = NtQuerySystemInformation( \
                win32con.SYSTEM_PROCESS_INFORMATION, \
                buf, \
                bufferSize, \
                byref(returnLength) )
        if win32con.STATUS_SUCCESS == status:
            break
        elif win32con.STATUS_INFO_LENGTH_MISMATCH != status:
            raise Exception("Query info error")
        bufferSize *= 2
    results = []
    processInfo = cast(addressof(buf), c_POINTER(SYSTEM_PROCESS_INFORMATION_DETAILD)).contents
    offset = processInfo.NextEntryOffset
    # Skip the first one
    processInfo = cast(addressof(buf) + offset, c_POINTER(SYSTEM_PROCESS_INFORMATION_DETAILD)).contents
    while True:
        results.append((processInfo.ImageName.Buffer, processInfo.UniqueProcessId))
        if 0 == processInfo.NextEntryOffset:
            break
        offset += processInfo.NextEntryOffset
        processInfo = cast(addressof(buf) + offset, c_POINTER(SYSTEM_PROCESS_INFORMATION_DETAILD)).contents
    return results

def enumProcesses():
    adjustDebugPrivileges()

    processesIds = c_uint32 * 0x4096
    processesIds = processesIds()
    cb = sizeof(processesIds)
    bytesReturned = c_uint32()
    EnumProcesses(
            byref(processesIds),
            cb,
            byref(bytesReturned))
    processes = bytesReturned.value // sizeof(c_uint32())

    results = []
    module  = c_uint32()
    count   = c_uint32()
    for i in range(processes):
        if processesIds[i] == 0:
            continue
        try:
            process = OpenProcess(
                        win32con.PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        processesIds[i])
        except WindowsError as e:
            if 5 == e.winerror:
                continue
            raise e
        if process:
            moduleName = c_wchar_p('A' * 2048)
            try:
                name = GetProcessImageFileName(process, moduleName, len(moduleName.value))
                if len(name) <= 4:
                    continue
            except WindowsError as e:
                if 87 == e.winerror:
                    # print("Failed to get module name for process %d (%r)" % (process, e))
                    continue
                if 299 != e.winerror:
                    raise e
            results.append((moduleName.value, processesIds[i]))
    return results

def findProcessId(name):
    target = name.lower()
    results = []
    processes = enumProcesses()
    for process in processes:
        if target in process[0].lower():
            results.append(process)
    return results


def clip(value):
    import ctypes
    strcpy = ctypes.cdll.msvcrt.strcpy
    ocb = ctypes.windll.user32.OpenClipboard    #Basic Clipboard functions
    ecb = ctypes.windll.user32.EmptyClipboard
    scd = ctypes.windll.user32.SetClipboardData
    ccb = ctypes.windll.user32.CloseClipboard
    ga = ctypes.windll.kernel32.GlobalAlloc    # Global Memory allocation
    gl = ctypes.windll.kernel32.GlobalLock     # Global Memory Locking
    gul = ctypes.windll.kernel32.GlobalUnlock
    ocb(None) # Open Clip, Default task
    ecb()
    hCd = ga( 0x2000, len(value)+1 )
    pchData = gl(hCd)
    strcpy(ctypes.c_char_p(pchData),value)
    gul(hCd)
    scd(1,hCd)
    ccb()

