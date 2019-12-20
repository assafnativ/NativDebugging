#
#   WindowsMemoryReading.py
#
#   Example of how to use MemoryReader on Windows
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

from NativDebugging.Win32 import MemoryReader
import os
import time

os.system('calc')
time.sleep(1)
process_id = MemoryReader.findProcessId('Calculator')[0][1]
m = MemoryReader.attach(process_id)
base = m.findModule(b'Calculator')
m.dd(base)
m.db(base)
