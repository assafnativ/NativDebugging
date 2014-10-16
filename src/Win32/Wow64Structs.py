
from ctypes import c_uint64, c_int32, c_uint32, c_void_p, windll, WinError
import sys
import os

if '32 ' in sys.version:
    dirName = os.path.dirname(__file__)
    target = os.sep.join([dirName, 'wow64ext'])
    wow64ext = windll.LoadLibrary(target)
    ReadProcessMemory64 = wow64ext.ReadProcessMemory64
    ReadProcessMemory64.argtypes = [
        c_int32,    # hProcess // handle to the process
        c_uint64,   # lpBaseAddress // base of memory area
        c_void_p,   # lpBuffer // data buffer
        c_uint32,   # nSize // number of bytes to read
        c_void_p]   # lpNumberOfBytesWritten // number of bytes write
    ReadProcessMemory64.restype = c_uint32
