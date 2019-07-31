#
#   PatternsSample.py
#
#   Example of how to use Memory Patterns
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

from NativDebugging.Patterns.Finder import *
from NativDebugging.Win32 import MemoryReader
import subprocess
import time
import sys

process = None
if len(sys.argv) < 2:
    process = subprocess.Popen('c:/windows/system32/winver.exe')
    time.sleep(1)
    targetPid = process.pid
else:
    targetPid = int(sys.argv[1])

m = MemoryReader.attach(targetPid)
base = m.findModule('kernel32.dll')
print("Found kernel base at %x" % base)
patFinder = CreatePatternsFinder(m)

# Shape is made of name, range, type, extra_check_function
pePat = [
    SHAPE('megic', 0, n_string(fixedValue=b'MZ')),
    SHAPE('peOffset', (0x10, 0x80), n_number((0x80, 0x1000), size=2), lambda ctx,value:b'PE' == m.readMemory(base + value, 2)),
    SHAPE('msg', 0x10, n_string(fixedValue=b'This program'))]

print(patFinder.searchOne(pePat, base))

if process:
    process.kill()
