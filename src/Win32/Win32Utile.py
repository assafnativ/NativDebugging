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
    for i in xrange(processes):
        if processesIds[i] == 0:
            continue
        try:
            process = OpenProcess(
                        win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                        0,
                        processesIds[i])
        except WindowsError, e:
            if 5 == e.winerror:
                continue
            raise e
        if process:
            moduleName = c_buffer(0x100)
            try:
                EnumProcessModules(process, byref(module), sizeof(module), byref(count))
                GetModuleBaseName(process, module.value, moduleName, sizeof(moduleName))
            except WindowsError, e:
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


