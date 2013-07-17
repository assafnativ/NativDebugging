from ctypes import *
from .Win32Structs import *

def adjustDebugPrivileges():
    access_token = c_void_p(0)
    privileges = TOKEN_PRIVILEGES()

    OpenProcessToken( GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES, byref(access_token) )
    access_token = access_token.value
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

def enumProcesses():
    bufferSize = 0x1000
    while True:
        buf = create_string_buffer(bufferSize)
        returnLength = c_uint(0)
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
    processInfo = cast(addressof(buf), POINTER(SYSTEM_PROCESS_INFORMATION_DETAILD)).contents
    offset = processInfo.NextEntryOffset
    # Skip the first one
    processInfo = cast(addressof(buf) + offset, POINTER(SYSTEM_PROCESS_INFORMATION_DETAILD)).contents
    while True:
        #print processInfo.UniqueProcessId, processInfo.ImageName.Buffer
        results.append((processInfo.ImageName.Buffer, processInfo.UniqueProcessId))
        if 0 == processInfo.NextEntryOffset:
            break
        offset += processInfo.NextEntryOffset
        processInfo = cast(addressof(buf) + offset, POINTER(SYSTEM_PROCESS_INFORMATION_DETAILD)).contents
    return results
        
def _enumProcessesOld():
    adjustDebugPrivileges()
    
    processesIds = c_uint * 0x400
    processesIds = processesIds()
    cb = sizeof(processesIds)
    bytesReturned = c_uint()
    EnumProcesses(
            byref(processesIds),
            cb,
            byref(bytesReturned))
    processes = bytesReturned.value / sizeof(c_ulong())

    results = []
    module  = c_ulong()
    count   = c_ulong()
    for i in range(processes):
        if processesIds[i] == 0:
            continue
        try:
            process = OpenProcess(
                        win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                        0,
                        processesIds[i])
        except WindowsError as e:
            if 5 == e.winerror:
                continue
            raise e
        if process:
            moduleName = c_buffer(0x100)
            try:
                EnumProcessModules(process, byref(module), sizeof(module), byref(count))
                GetModuleBaseName(process, module.value, moduleName, sizeof(moduleName))
            except WindowsError as e:
                if 299 != e.winerror:
                    raise e
            results.append((moduleName.value.replace('\x00', ''), processesIds[i]))
    return results
                
def findProcessId(name):
    results = []
    processes = enumProcesses()
    for process in processes:
        if process[0].lower().startswith(name):
            results.append(process)
    return results


