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


def makeQwordsList( data ):
    if len(data) % 8 != 0:
        data += '\x00' * (8 - (len(data) % 8))
    return list(struct.unpack('=' + ('Q' * (len(data) / 8)), data))

def makeDwordsList( data ):
    if len(data) % 4 != 0:
        data += '\x00' * (4 - (len(data) % 4))
    return list(struct.unpack('=' + ('L' * (len(data) / 4)), data))

def makeWordsList( data ):
    if len(data) % 2 != 0:
        data += '\x00' * (2 - (len(data) % 2))
    return list(struct.unpack('=' + ('H' * (len(data) / 2)), data))

def makeBytesList( data ):
    return list(map(ord, data))

def printIntTable( table, base = 0, itemSize=4, itemsInRow = 0x8 ):
    result = ''
    result += ' ' * 17
    itemStr = '%%%dx' % (itemSize * 2)
    for i in range(itemsInRow):
        result += itemStr % (i * itemSize)
        result += ' '
    result += '\n'
    for i in range(0, len(table), itemsInRow):
        if 0 == base:
            line = '%16x ' % (i * 4 )
        else:
            line = '%16x ' % ((i * 4) + base)
        line_data = table[i:][:itemsInRow]
        for t in line_data:
            line += itemStr % t
            line += ' '
        spacesLeft = ((itemSize * 2 + 1) * itemsInRow) + 19
        line += ' ' * (spacesLeft - len(line))
        for t in line_data:
            for x in struct.pack('=L', t):
                if( x == repr(x)[1] ):
                    line += x
                else:
                    line += '.'
        line += '\n'
        result += line
    print(result)

def printAsQwordsTable( data, base = 0, itemsInRow = 0x8 ):
    table = makeQwordsList(data)
    printIntTable(table, base, itemSize=8, itemsInRow=itemsInRow)
    return table

def printAsDwordsTable( data, base = 0, itemsInRow = 0x8 ):
    table = makeDwordsList(data)
    printIntTable(table, base, itemSize=4, itemsInRow=itemsInRow)
    return table

def printAsWordsTable( data, base = 0, itemsInRow = 0x8 ):
    table = makeWordsList(data)
    printIntTable(table, base, itemSize=2, itemsInRow=itemsInRow)
    return table

def hex2data( h ):
    result = ''
    for i in range(0,len(h),2):
        result += chr(int(h[i:i+2],16))
    return result

def data2hex( d ):
    result = ''
    for i in d:
        result += '%02X' % ord(i)
    return result

def hex2dword(x):
    return struct.unpack('=L', hex2data(x))[0]

def buffDiff( buffers, chunk_size = 1 ):
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
                        print("Buff diff at {0:04X}: ".format(i)),
                        for chunk in chunks:
                            print("{0:02X} ".format(ord(chunk))),
                        print
                    elif( 2 == chunk_size ):
                        print("Buff diff at {0:04X}: ".format(i)),
                        for chunk in chunks:
                            print("{0:04X} ".format(struct.unpack('=H',chunk)[0])),
                        print
                    elif( 4 == chunk_size ):
                        print("Buff diff at {0:04X}: ".format(i)),
                        for chunk in chunks:
                            print("{0:08X} ".format(struct.unpack('=L',chunk)[0])),
                        print
                    else:
                        print("Buff diff at {0:04X}: ".format(i)),
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

def getIpcsInfo(isVerbos=True):
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
    if isVerbos:
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


