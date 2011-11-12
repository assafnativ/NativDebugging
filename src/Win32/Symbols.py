#
#   Symbols.py
#
#   pyMint - Remote process memory inspection python module
#   https://code.google.com/p/pymint/
#   Nativ.Assaf+pyMint@gmail.com
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


from .Win32Structs import *

collectedSymbols = []

def getSymbols( fileName ):
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


