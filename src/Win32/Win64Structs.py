from ctypes import c_int32, c_void_p, windll, WinError

def ErrorIfZero(handle):
    if handle == 0:
        raise WinError()
    else:
        return handle

IsWow64Process = windll.kernel32.IsWow64Process
IsWow64Process.argtypes = [
                c_int32,
                c_void_p ]
IsWow64Process.restype = ErrorIfZero
