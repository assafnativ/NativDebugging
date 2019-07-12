from NativDebugging.Win32.MemReaderOverRPyC import createProcess

notepad = createProcess(r'C:\Windows\System32\notepad.exe')
rnd = notepad.NativDebugging
RegisterClassProto = rnd.WINFUNCTYPE(
        rnd.c_void_p, rnd.c_void_p)
RegisterClass = RegisterClassProto(
        ("RegisterClassW", rnd.user32),
        ((1, "WndClass", None),))
IsWindowVisible = rnd.WINFUNCTYPE(
        rnd.c_uint32, rnd.c_void_p)(
                ('IsWindowVisible', rnd.user32),
                ((1, 'hWnd', None),))
GetWindowThreadProcessId = rnd.WINFUNCTYPE(
        rnd.c_uint32, rnd.c_void_p, rnd.c_void_p)(
                ('GetWindowThreadProcessId', rnd.user32),
                ((1, 'hWnd', None), (1, 'processId', None)))
EnumWindows = rnd.WINFUNCTYPE(
        rnd.c_uint32, rnd.c_void_p, rnd.c_void_p)(
                ('EnumWindows', rnd.user32),
                ((1, 'EnumFunc', None), (1, 'lParam', None)))
GetWindowLongPtr = rnd.WINFUNCTYPE(
        rnd.c_void_p, rnd.c_void_p, rnd.c_int32)(
                ('GetWindowLongPtrW', rnd.user32),
                ((1, 'hWnd', None), (1, 'index', -4)))
WindowProcProto = rnd.WINFUNCTYPE(
        rnd.c_void_p, rnd.c_void_p, rnd.c_uint32, rnd.c_void_p, rnd.c_void_p)

@WindowProcProto
def wndProcHook(hwnd, umsg, wParam, lParam):
    print("HWND: %x send message %x (%x, %x)" % (hwnd, umsg, wParam, lParam))
    return notepad.originalFunctions[wndProcAddr](hwnd, umsg, wParam, lParam)

wndProcAddr = 0
EnumWindowsCallback = rnd.WINFUNCTYPE(rnd.c_uint32, rnd.c_void_p, rnd.c_void_p)
@EnumWindowsCallback
def callback(handle, lParam):
    global wndProcAddr
    if not handle:
        return 0xffffffff
    windowProcess = rnd.c_void_p(0)
    GetWindowThreadProcessId(handle, rnd.byref(windowProcess))
    if windowProcess.value != rnd.os.getpid():
        return 0xffffffff
    windowVisible = IsWindowVisible(handle)
    if not windowVisible:
        return 0xffffffff
    wndProcAddr = GetWindowLongPtr(handle, -4)
    notepad.hook(wndProcAddr, WindowProcProto, wndProcHook)
    print('HWND: %x, %x, %x' % (handle, windowVisible, wndProcAddr))
    return 0xffffffff

print("Notepad process id: %x" % (rnd.os.getpid()))
EnumWindows(callback, 0)

#@RegisterClassProto
#def registerClassHook(wndClass):
#    print("Registering class: %x" % wndClass.value)
#    return notepad.originalFunctions[registerClass_addr](wndClass)
#
#registerClass_addr = notepad.getCTypeProcAddress(RegisterClass)
#notepad.hook(registerClass_addr, RegisterClassProto, registerClassHook)
