def printCreateFile(dc, isUnicode):
    esp = dc.context.esp
    returnAddress = dc.readAddr(esp)
    fname = dc.readAddr(esp + 4)
    access = dc.readDword(esp + 8)
    sharedMode = dc.readDword(esp + 0xc)
    securityAttrib = dc.readAddr(esp + 0x10)
    creationDispos = dc.readDword(esp + 0x14)
    flags = dc.readDword(esp + 0x18)
    template = dc.readAddr(esp + 0x1c)
    print "Fanem: ", dc.readString(fname, isUnicode=isUnicode)
    print "Return address: %x" % returnAddress
    print "Access: %x" % access
    print "Shared mode: %x" % sharedMode
    print "SecurityAttrib: %x" % securityAttrib
    print "Creation dispos: %x" % creationDispos
    print "Flags: %x" % flags
    print "Template: %x" % template

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
# To solve a race condition bug...
time.sleep(1)
d.run()
time.sleep(1)
d.bpx(d.findProcAddress('kernel32.dll', 'CreateFileW'), printCreateFileW)
d.bpx(d.findProcAddress('kernel32.dll', 'CreateFileA'), printCreateFileA)
d.run()

while d.isProcessAlive():
    pass
    
