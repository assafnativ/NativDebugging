#
#   win64structs.py
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

# Imports  
from ctypes import *

def ErrorIfZero(handle):
    if handle == 0:
        raise WinError()
    else:
        return handle

IsWow64Process = windll.kernel32.IsWow64Process
IsWow64Process.argtypes = [
		c_int,
		c_void_p ]
IsWow64Process.restype = ErrorIfZero
