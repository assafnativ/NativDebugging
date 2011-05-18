# Copyright 2010 Assaf Nativ
#    This file is part of Candy.
#
#    Candy is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Candy is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Candy.  If not, see <http://www.gnu.org/licenses/>.

from NativDebugging.Patterns import *
from NativDebugging.Win32 import MemoryReader
import sys

if len(sys.argv) < 2:
    raise Exception('Need process id')

m = MemoryReader.attach(int(sys.argv[1]))
base = m.findModule('kernel32.dll')
patFinder = CreatePatternsFinder(m)

# Shape is made of name, range, type, extra_check_function
pePat = [
    SHAPE('megic', 0, STRING(fixedValue='MZ')),
    SHAPE('peOffset', 0x80, NUMBER((0x80, 0x1000), size=2), lambda ctx,value:'PE' == m.readMemory(base + value, 2)),
    SHAPE('msg', 0x10, STRING(fixedValue='This program'))]

for i in patFinder.search(pePat, base):
    result = i

print( result )

