#
#   HookWin32.py
#
#   Example of how to hook something on Windows
#   https://github.com/assafnativ/NativDebugging.git
#   Nativ.Assaf@gmail.com
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

import os
import time
from builtins import bytes
from NativDebugging.Win32.Debugger import create
from NativDebugging.Win32.Win32Structs import *


notepad = create(r'C:\Windows\System32\notepad.exe')
notepad.pos = 0
notepad.text = open(__file__, 'rb').read()
if not isinstance(notepad.text[0], (int,)):
    notepad.text = [ord(x) for x in notepad.text]
notepad.text = [x for x in notepad.text if x != 0xd]

def wndProcHook(self):
    umsg = self.context.rdx
    if 0x102 != umsg:
        return
    hwnd = self.context.rcx
    wParam = self.context.r8
    lParam = self.context.r9
    wParam = (wParam & 0xffffffffffffff00) + self.text[notepad.pos]
    self.context.r8 = wParam
    self.setCurrentContext()
    self.pos += 1

def registerClassHook(self):
    wndClassPtr = self.context.rcx
    print("Registering class: %x" % wndClassPtr)
    cbSize = self.readUInt32(wndClassPtr)
    wndProc = self.readAddr(wndClassPtr + 8)
    print("wndProc: %x" % wndProc)
    classNamePtr = self.readAddr(wndClassPtr + 0x40)
    if classNamePtr:
        className = self.readString(classNamePtr, isUnicode=True)
        print("Class Name: %s" % className)
        if ('edit' == className.lower()):
            notepad.bpx(wndProc, wndProcHook)
    else:
        print("No class name!")
        self.dq(wndClassPtr)

notepad.breakOnModuleLoad = True
user32 = -1
while True:
    while notepad.isProcessRunning():
        pass
    user32 = notepad.getModuleBase('user32.dll')
    if -1 != user32:
        break
    notepad.run()
print("Found user32 at %x" % user32)

registerClass_addr = notepad.findProcAddress('user32.dll', b'RegisterClassW')
print("Hooking: %x" % registerClass_addr)
notepad.bpx(registerClass_addr, registerClassHook)
notepad.breakOnModuleLoad = False
notepad.run()
while True:
    pass
