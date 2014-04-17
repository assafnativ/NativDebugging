#
#   Symbols.py
#
#   Win32 executables symbols handler for python
#   https://xp-dev.com/svn/nativDebugging/
#   Nativ.Assaf@gmail.com
#   Copyright (C) 2013  Assaf Nativ
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

# This class sucks 
# I need to rewrite it from the begging
# Meanwhile use the pdbparse module

from .Win32Structs import *
import urllib2
import time
import datetime
import threading

collectedSymbols = []

def downloadBinaryFromSymbolsServer( filename, date_time, file_size ):
    if isinstance(date_time, str):
        date_time = int(time.mktime(time.strptime(date_time)))
    elif not isinstance(date_time, (int, long)):
        date_time = int(time.mktime(date_time))
    url  = "http://msdl.microsoft.com/download/symbols/"
    url += filename
    url += "/"
    url += "%x" % date_time
    url += "%x" % file_size
    url += "/"
    url += filename[:-1] + '_'
    req = urllib2.Request(url=url)
    req.add_header("Accept-Encoding", "gzip")
    req.add_header("User-Agent", "Microsoft-Symbol-Server/6.2.8250.0")
    req.add_header("Host", "msdl.microsoft.com")
    req.add_header("Connection", "Keep-Alive")
    req.add_header("Cache-Control", "no-cache")
    try:
        res = urllib2.urlopen(req)
    except urllib2.HTTPError, e:
        if 404 == e.getcode():
            return
    data = res.read()
    res.close()
    return data

def _setStartAndEndDate(date, end_date=None):
    if isinstance(date, tuple):
        start = int(time.mktime((date[0], date[1], date[2], 0, 0, 0, 0, 0, 0)))
    elif isinstance(date, (int, long)):
        start = date
    else:
        raise Exception("Don't know how to translate the date to int")
    # Make the end time/date the begging of the next day
    if None != end_date:
        end = end_date
    else:
        start_date = datetime.date.fromtimestamp(start)
        end = start_date + datetime.timedelta(days=1)
        end = int(time.mktime(time.strptime(end.ctime())))
    if end <= start:
        raise Exception("Faild to caculate the end date %x" % end)
    return (start, end)

def bruteForceDateTimeDownload(filename, date, file_size, end_date=None, is_verbose=True):
    start, end = _setStartAndEndDate(date, end_date)
    function_timing = time.time()
    if is_verbose:
        print "Starting from timestamp %x" % start
        print "Would end on timestamp  %x" % end
    for date_time in range(start, end):
        try:
            r = downloadBinaryFromSymbolsServer(filename, date_time, file_size)
            if None != r:
                print hex(date_time)
                return r
            attempts = 0
            if is_verbose and date_time == (date_time & 0xfffffff0):
                running_time = time.time() - function_timing
                number_of_execuations = date_time - start
                avg = float(number_of_execuations) / running_time
                if 0 != avg:
                    left = end - date_time
                    left_sec = float(left) / avg
                    print "Last attempt:", hex(date_time), "Secs passed:", int(running_time), "Avg of", avg, "quries/sec. ~%f secs left" % left_sec
        except Exception, e:
            print e
            attempts += 1
            if attempts > 3:
                raise e
            time.sleep(2)

class CreateBruteForceThread(threading.Thread):
    def __init__(self, filename, start, end, file_size, is_verbose=True):
        self.filename = filename
        self.start = start
        self.end = end
        self.file_size = file_size
        self.is_verbose = is_verbose
        self.result = None
        threading.Thread.__init__(self)
    def run(self):
        self.result = bruteForceDateTimeDownload(self.filename, self.start, self.file_size, self.end)

# Fix this shit
def runMuntiThreadBruteForce(filename, start, file_size, end_date=None, num_threads=10, is_verbose=True):
    start, end = _setStartAndEndDate(date, end_date)
    last_start = start
    thread_range = 0x1000
    running_threads = []
    result = None
    while None == result:
        if len(running_threads) < num_threads:
            t = CreateBruteForceThread(filename, last_start, last_start + thread_range, file_size, is_verbose)
            running_threads.append(t)
            last_start += thread_range

def getSymbols(fileName):
    global collectedSymbols

    options = SymGetOptions()
    options |= SYMOPT_DEBUG
    SymSetOptions( options )

    currentProcess = GetCurrentProcess()
    SymInitialize( currentProcess, None, False )

    base = SymLoadModule64( currentProcess, 0, fileName, None, 0, 0 )
    collectedSymbols = []
    SymEnumSymbols( currentProcess, base, None, collectSymbols, None )

    SymUnloadModule64( currentProcess, base )
    SymCleanup( currentProcess )

    return collectedSymbols

def collectSymbols_python( symInfo, symbolSize, ctx ):
    global collectedSymbols

    if False != bool(symInfo):
        symInfo = symInfo.contents
        collectedSymbols.append( (symInfo.Name, symInfo.Address) )
    return True

collectSymbols = SYM_ENUMERATESYMBOLS_CALLBACK(collectSymbols_python)

def parseSymbolsDump( symbols_dump ):
    result = []
    f = file(symbols_dump, 'r')
    for l in f.readlines():
        address_pos = l.find('Address: ')
        name_pos = l.find('Name: ')
        if -1 == address_pos or -1 == name_pos:
            continue
        address_pos += len('Address: ')
        name_pos += len('Name: ')
        result.append( (l[name_pos:l.find('\n')], int(l[address_pos:address_pos + l[address_pos:].find(' ')], 16)) )
    f.close()
    return result

def findSymbol( name, symbols, base=0, isCaseSensitive = True ):
    if False == isCaseSensitive:
        name = name.lower()
    for sym in symbols:
        if False == isCaseSensitive:
            symName = sym[0].lower()
        else:
            symName = sym[0]
        if name == symName:
            return sym[1] + base
    return 0

def findContaining( subText, symbols, base=0, isCaseSensitive = False ):
    if False == isCaseSensitive:
        if type(subText) == type(''):
            subText = subText.lower()
        elif type(subText) == type([]):
            subText = [x.lower() for x in subText]
    for sym in symbols:
        if False == isCaseSensitive:
            symName = sym[0].lower()
        else:
            symName = sym[0]
        if type(subText) == type(''):
            if subText in symName:
                print('0x{0:x} {1:s}'.format(sym[1]+base, sym[0]))
        elif type(subText) == type([]):
            for st in subText:
                if st not in symName:
                    break
            else:
                print('0x{0:x} {1:s}'.format(sym[1]+base, sym[0]))

def solveAddr( addr, symbols, base = 0 ):
    for sym in symbols:
        if sym[1]+base == addr:
            return( sym[0] )
    return None


