#
#   utile.py
#
#   Utile - Utile functions and procedures for NativDebugging
#   https://svn3.xp-dev.com/svn/nativDebugging/
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2011  Assaf Nativ
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

# Platform independent

import struct
import sys
import os
import subprocess

if sys.platform == 'win32':
    from .Win32.Win32Utile import *

def DATA( data, base = 0, itemsInRow=0x10 ):
    result = ''
    for i in range(0, len(data), itemsInRow):
        line = '%08X  ' % (i + base)
        line_data = data[i:][:itemsInRow]
        for t in range(len(line_data)):
            if( (0 == (t % 8)) and (t > 0) ):
                line += '- %02X' % ord(line_data[t])
            elif( 0 == (t & 1) ):
                line += '%02X' % ord(line_data[t])
            elif( 1 == (t & 1) ):
                line += '%02X ' % ord(line_data[t])
            
        spacesLeft = 13 + int(itemsInRow * 2.5) + (2 * ((itemsInRow - 1)//8))
        line += ' ' * (spacesLeft - len(line))
        for t in line_data:
            if( t == repr(t)[1] ):
                line += t
            else:
                line += '.'
        line += '\n'
        result += line
    return( result )


def makeQwordsList( data, endianity='=' ):
    if len(data) % 8 != 0:
        data += '\x00' * (8 - (len(data) % 8))
    return list(struct.unpack(endianity + ('Q' * (len(data) / 8)), data))

def makeDwordsList( data, endianity='=' ):
    if len(data) % 4 != 0:
        data += '\x00' * (4 - (len(data) % 4))
    return list(struct.unpack(endianity + ('L' * (len(data) / 4)), data))

def makeWordsList( data, endianity='=' ):
    if len(data) % 2 != 0:
        data += '\x00' * (2 - (len(data) % 2))
    return list(struct.unpack(endianity + ('H' * (len(data) / 2)), data))

def makeBytesList( data ):
    return list(map(ord, data))

def printIntTable( table, base = 0, itemSize=4, itemsInRow = 0x8, endianity='=' ):
    result = ''
    result += ' ' * 17
    itemStr = '%%%dx' % (itemSize * 2)

    if 2 == itemSize:
        packSize = endianity + 'H'
    elif 4 == itemSize:
        packSize = endianity + 'L'
    elif 8 == itemSize:
        packSize = endianity + 'Q'
    else:
        raise Exception("Invalid size for print table")

    for i in range(itemsInRow):
        result += itemStr % (i * itemSize)
        result += ' '
    result += '\n'
    for i in range(0, len(table), itemsInRow):
        if 0 == base:
            line = '%16x ' % (i * itemSize )
        else:
            line = '%16x ' % ((i * itemSize) + base)
        line_data = table[i:][:itemsInRow]
        for t in line_data:
            line += itemStr % t
            line += ' '
        spacesLeft = ((itemSize * 2 + 1) * itemsInRow) + 19
        line += ' ' * (spacesLeft - len(line))
        for t in line_data:
            for x in struct.pack(packSize, t):
                if( x == repr(x)[1] ):
                    line += x
                else:
                    line += '.'
        line += '\n'
        result += line
    print(result)

def printAsQwordsTable( data, base = 0, itemsInRow = 0x8, endianity='=' ):
    table = makeQwordsList(data, endianity=endianity)
    printIntTable(table, base, itemSize=8, itemsInRow=itemsInRow)
    return table

def printAsDwordsTable( data, base = 0, itemsInRow = 0x8, endianity='=' ):
    table = makeDwordsList(data, endianity=endianity)
    printIntTable(table, base, itemSize=4, itemsInRow=itemsInRow)
    return table

def printAsWordsTable( data, base = 0, itemsInRow = 0x8, endianity='=' ):
    table = makeWordsList(data, endianity=endianity)
    printIntTable(table, base, itemSize=2, itemsInRow=itemsInRow)
    return table

def hex2data( h ):
    if h[:2] == '0x':
        return h[2:].decode('hex')
    return h.decode('hex')

def data2hex( d ):
    return d.encode('hex')

def data2dword(x, endianity='='):
    return struct.unpack(endianity + 'L', x)[0]

def dword2data(x, endianity='='):
    return struct.pack(endianity + 'L', x)

def buffDiff( buffers, chunk_size = 1, endianity='=' ):
    if type(buffers) != type([]):
        print('Invalid type')
        return
    l = len(buffers[0])
    for i in buffers:
        if( type(i) == type([]) ):
            for j in i:
                if( len(j) < l ):
                    l = len(j)
        else:
            if( len(i) < l ):
                l = len(i)
    i = 0
    total_diffs = 0
    while l - i >= chunk_size:
        chunks = []
        diff_this_chunk = True
        for buff in buffers:
            if type(buff) == type([]):
                chunk0 = buff[0][i:i+chunk_size]
                for sub_buff in buff:
                    if sub_buff[i:i+chunk_size] != chunk0:
                        diff_this_chunk = False
                        break
                if False == diff_this_chunk:
                    break
                else:
                    chunks.append(chunk0[:])
            else:
                chunks.append( buff[i:i+chunk_size] )

        if True == diff_this_chunk:
            #chunks = map(lambda x:x[i:i+chunk_size], buffers)
            chunk0 = chunks[0]
            for chunk in chunks:
                if chunk != chunk0:
                    if( 1 == chunk_size ):
                        print("Buff diff at {0:X}: ".format(i)),
                        for chunk in chunks:
                            print("{0:02X} ".format(ord(chunk))),
                        print
                    elif( 2 == chunk_size ):
                        print("Buff diff at {0:X}: ".format(i)),
                        for chunk in chunks:
                            print("{0:04X} ".format(struct.unpack(endianity + 'H',chunk)[0])),
                        print
                    elif( 4 == chunk_size ):
                        print("Buff diff at {0:X}: ".format(i)),
                        for chunk in chunks:
                            print("{0:08X} ".format(struct.unpack(endianity + 'L',chunk)[0])),
                        print
                    else:
                        print("Buff diff at {0:X}: ".format(i)),
                        for chunk in chunks:
                            print("\t{0:s}".format(data2hex(chunk))),
                    total_diffs += 1
                    break
        i += chunk_size
    if( 0 == total_diffs ):
        print("Buffers match!")
    else:
        print("Total diffs %d" % total_diffs)

def dotted(ip):
    result = '%d.%d.%d.%d' % ((ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff)
    return result

def getIpcsInfo(isVerbose=True):
    if sys.platform.lower().startswith('win32'):
        raise Exception("This function is not supported under Windows platform")
    if sys.platform.lower().startswith('linux'):
        command = ['ipcs', '-m']
    elif sys.platform.lower().startswith('sunos'):
        command = ['ipcs', '-mb']
    elif sys.platform.lower().startswith('aix'):
        command = ['ipcs', '-mb']
    elif sys.platform.lower().startswith('hp-ux'):
        command = ['ipcs', '-mb']
    else:
        command = ['ipcs', '-m']
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    out,err = p.communicate()
    lines = out.split(os.linesep)
    if isVerbose:
        for i in lines:
            print(i)
    return lines 

def getAllShmidsInfo(ownerFilter=None):
    if sys.platform.lower().startswith('win32'):
        raise Exception("This function is not supported under Windows platform")
    if sys.platform.lower().startswith('linux'):
        SHMID_INDEX = 1
        KEY_INDEX = 0
        SIZE_INDEX = 4
        OWNER = 2
    elif sys.platform.lower().startswith('sunos'):
        SHMID_INDEX = 1
        KEY_INDEX = 2
        SIZE_INDEX = 6
        OWNER = 4
    elif sys.platform.lower().startswith('aix'):
        SHMID_INDEX = 1
        KEY_INDEX = 2
        SIZE_INDEX = 6
        OWNER = 4
    elif sys.platform.lower().startswith('hp-ux'):
        SHMID_INDEX = 1
        KEY_INDEX = 2
        SIZE_INDEX = 6
        OWNER = 4
    else:
        # Defaults
        SHMID_INDEX = 1
        KEY_INDEX = 0
        SIZE_INDEX = 4
        OWNER = 2
    memInfo = getIpcsInfo(False)
    res = []
    # We don't know how many lines belong to the header, so we try to parse it until we fail
    for i in memInfo:
        sLine = i.split()
        try:
            owner  = sLine[OWNER]
            if None != ownerFilter and owner != ownerFilter:
                continue
            shmid  = int(sLine[SHMID_INDEX])
            key    = sLine[KEY_INDEX]
            if key[:2] == '0x':
                key = key[2:]
            key = int(key,16)
            shSize = int(sLine[SIZE_INDEX])
            res.append((key,shmid,shSize))
        except ValueError: 
            pass
        except IndexError:
            pass
    #res[(key,shmid,shSize)]
    return res

def getShmids(ownerFilter=None):
    if sys.platform == 'win32':
        raise Exception("This function is not supported under Windows platform")
    memInfo = getAllShmidsInfo(ownerFilter)
    return [x[1] for x in memInfo]

def getShmidsWithSizes(ownerFilter=None):
    if sys.platform == 'win32':
        raise Exception("This function is not supported under Windows platform")
    memInfo = getAllShmidsInfo(ownerFilter)
    return [(x[1], x[2])  for x in memInfo]

def getMemMapFromPMaap(pid):
    if sys.platform == 'win32':
        raise Exception("This function is not supported under Windows platform")
    elif sys.platform.startswith('aix'):
        raise Exception("This function is not supported under AIX")
    lines = subprocess.Popen("pmap %d" % pid, stdout=PIPE, shell=True).communicate()[0].split('\n')
    memInfo = []
    for l in lines:
        l = l.strip()
        if l.startswith('%d: ' % pid):
            continue
        if l.lower().startswith('start'):
            continue
        if len(l) < 2:
            continue
        values = l.split()
        if sys.platform.lower().startswith('linux') or sys.platform.lower().startswith('sunos'):
            startAddr = int(values[0], 16)
            segmentSize = values[1].lower()
            permStr = values[2].lower()
            name = values[3]
        elif sys.platform.startswith('hp-ux'):
            startAddr = int(values[0], 16)
            segmentSize = values[1].lower()
            permStr = values[4].lower()
            name = values[5]
        else:
            raise Exception("Platform %s not supported for this function" % sys.platform)
        if segmentSize.endswith('b'):
            segmentSize = int(segmentSize[:-1])
        elif segmentSize.endswith('k'):
            segmentSize = int(segmentSize[:-1]) * 1024
        elif segmentSize.endswith('m'):
            segmentSize = int(segmentSize[:-1]) * 1024 * 1024
        elif segmentSize.endswith('g'):
            segmentSize = int(segmentSize[:-1]) * 1024 * 1024 * 1024
        else:
            segmentSize = int(segmentSize)
        perm = 0
        if 'r' in permStr:
            perm |= 0x40
        elif 'w' in permStr:
            perm |= 0x80
        elif 'x' in permStr:
            perm |= 0x20
        memInfo.append((name, startAddr, segmentSize, perm))
    return memInfo

def clipHex(x):
    if sys.platform != 'win32':
        raise Exception("This funciton is not supported under *nix platforms")
    if hasattr(x, 'value'):
        value = hex(x.value)
    elif hasattr(x, 'address'):
        value = hex(x.address)
    else:
        value = hex(x)
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

_LAST_TRACEBACK = None
def loadExcptionLocals(step=1):
    global _LAST_TRACEBACK
    _LAST_TRACEBACK = sys.last_traceback
    exceptionUp(step)

def exceptionUp(step=1):
    global _LAST_TRACEBACK
    import __main__
    _LAST_TRACEBACK = _LAST_TRACEBACK
    for i in range(step):
        _LAST_TRACEBACK = _LAST_TRACEBACK.tb_next
    frame = _LAST_TRACEBACK.tb_frame
    print("Loading exception locals of file %s, line %d, in %s" % (frame.f_code.co_filename, _LAST_TRACEBACK.tb_lineno, frame.f_code.co_name))
    l = frame.f_locals
    for item in l.keys():
        if not item.startswith('_'):
            print("Adding: %s" % item)
            setattr(__main__, item, l[item])



