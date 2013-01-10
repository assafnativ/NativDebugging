
from NativDebugging.Patterns.PE import *
from NativDebugging.Win32.MemoryReader import *
from NativDebugging.Patterns.PatternsFinder import *
from NativDebugging.Win32.InjectDll import *

import os
import sys
import time

NtDLLCopy = os.path.abspath('.') + '\\NtCopy.dll'
targetPid = int(sys.argv[1])

print "Attaching memory reader"
m = attach(targetPid)
p = PatternFinder(m)

if not os.path.isfile(NtDLLCopy):
    ntdllPath = m.getModulePath('ntdll.dll')
    print "Copying %s -> %s" % (ntdllPath, NtDLLCopy)
    file(NtDLLCopy, 'wb').write(file(ntdllPath, 'rb').read())

print "Injecting %s to %d" % (NtDLLCopy, targetPid)
inject(targetPid, NtDLLCopy)

# Give the module some time to load
time.sleep(1)

print "Finding NtCopy.dll"
ntCopyAddr = m.findModule('NtCopy.dll')
ntCopyRVA = m.findRVA(ntCopyAddr)
print "NtCopy.dll loaded at 0x%x" % ntCopyAddr

print "Parsing exports of NtCopy.dll"
ntCopyImg = p.search(ImageDosHeader, ntCopyAddr).next()
exports = []
numProcs = ntCopyImg.PE.OptionalHeader.Exports.NumberOfFunctions
numNames = ntCopyImg.PE.OptionalHeader.Exports.NumberOfNames
names    = ntCopyImg.PE.OptionalHeader.Exports.NamesAddress + ntCopyAddr
ordinals = ntCopyImg.PE.OptionalHeader.Exports.NameOrdinalsAddress + ntCopyAddr
procs    = ntCopyImg.PE.OptionalHeader.Exports.FunctionsAddress + ntCopyAddr
for i in range(numProcs):
    ordinal = m.readWord(ordinals + (i * 2))
    if i < numNames:
        name    = m.readAddr(names + (i * m.getPointerSize()))
        if 0 != name:
            name = m.readString(ntCopyAddr + name)
        else:
            name = ""
    else:
        name = ""
    proc = m.readAddr(procs + (ordinal * m.getPointerSize())) + ntCopyAddr
    exports.append((name, ordinal, proc))

def fixImports(importsAddr, importsTableSize, dllAddr):
    for offset in range(0, importsTableSize, 0x14):
        name = m.readAddr(importsAddr + offset + 0xc)
        dllName = m.readString(dllAddr + name)
        if dllName.startswith("ntdll"):
            #print "Found imports from ntdll"
            namesTable = m.readAddr(importsAddr + offset) + dllAddr
            ptrsTable  = m.readAddr(importsAddr + offset + 0x10) + dllAddr
            procPtr = m.readAddr(ptrsTable)
            while 0 != procPtr:
                procName = m.readString(m.readAddr(namesTable) + dllAddr + 2)
                if len(procName) >= 2:
                    newProcAddr = None
                    for export in exports:
                        if export[0] == procName:
                            newProcAddr = export[2]
                            break
                    if None == newProcAddr:
                        raise Exception("Can't find %s in ntCopy.dll" % procName)
                    ntdllBytes  = m.readMemory(procPtr, 3)
                    copyBytes   = m.readMemory(newProcAddr, 3)
                    if ntdllBytes != copyBytes:
                        if copyBytes[0] == '\xb8':
                            print "Patch %s -> %s fixing from 0x%x to 0x%x name: %s" % (ntdllBytes.encode('hex'), copyBytes.encode('hex'), procPtr, newProcAddr, procName)
                            m.writeAddr(ptrsTable, newProcAddr)
                        else:
                            print "Patch %s -> %s not fixing from 0x%x to 0x%x name: %s" % (ntdllBytes.encode('hex'), copyBytes.encode('hex'), procPtr, newProcAddr, procName)
                namesTable += m.getPointerSize()
                ptrsTable += m.getPointerSize()
                procPtr = m.readAddr(ptrsTable)

for base, dllName, dllSize in m.enumModules():
    if dllName.startswith('NtCopy.dll'):
        continue
    print "Scanning 0x%x (%s)" % (base, dllName)
    img = p.search(ImageDosHeader, base).next()
    importsAddr = img.PE.OptionalHeader.AddressOfImports
    importsTableSize = img.PE.OptionalHeader.ImportDir.Size
    #print "Imports table address 0x%x" % importsAddr
    #print "Imports table size 0x%x" % importsTableSize
    if 0 != (importsTableSize % 0x14):
        print("Invalid import dir size %s (%d)" % (dllName, importsTableSize))
        continue
    fixImports(importsAddr, importsTableSize, base)

