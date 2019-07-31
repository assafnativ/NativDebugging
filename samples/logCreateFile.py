def printCreateFile(dc, isUnicode):
    esp = dc.context.esp
    returnAddress = dc.readAddr(esp)
    pointerSize = dc.getPointerSize()
    offset = pointerSize
    fname = dc.readAddr(esp + offset); offset += pointerSize
    access = dc.readUInt32(esp + offset); offset += 4
    sharedMode = dc.readUInt32(esp + offset); offset += 4
    securityAttrib = dc.readAddr(esp + offset); offset += pointerSize
    creationDispos = dc.readUInt32(esp + offset); offset += 4
    flags = dc.readUInt32(esp + offset); offset += 4
    template = dc.readAddr(esp + offset)
    print("Fname: ", dc.readString(fname, isUnicode=isUnicode))
    print("Return address: %x" % returnAddress)
    print("Access: %x" % access)
    print("Shared mode: %x" % sharedMode)
    print("SecurityAttrib: %x" % securityAttrib)
    print("Creation dispos: %x" % creationDispos)
    print("Flags: %x" % flags)
    print("Template: %x" % template)

def printCreateFileA(dc):
    printCreateFile(dc, False)

def printCreateFileW(dc):
    printCreateFile(dc, True)

import sys
import time
from NativDebugging.Win32.Debugger import *
target = findProcessId(sys.argv[1])
if len(target) > 0:
    target = target[0][1]
    d = attach(target)
else:
    d = create(sys.argv[1])
# To workaround a race condition bug...
while d.isProcessRunning():
    pass
d.run()
time.sleep(1)
d.bpx(d.findProcAddress('kernel32.dll', b'CreateFileW'), printCreateFileW)
d.bpx(d.findProcAddress('kernel32.dll', b'CreateFileA'), printCreateFileA)
d.run()

while d.isProcessAlive():
    pass

