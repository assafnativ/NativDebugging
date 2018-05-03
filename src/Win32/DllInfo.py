#
#   DllInfo.py
#
#   PyPepper - Win32 debugger python module
#   https://code.google.com/p/pypepper/
#   Nativ.Assaf+pyPepper@gmail.com
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

"""
File name:      BreakPoint.py
Define a class that contains all the information aboud a loaded dll.
Author: Assaf
Last date:
        17.03.06
"""

class DllInfo:
    def __init__( self, \
                  hFile, \
                  baseAddress, \
                  dwDebugInfoFileOffset, \
                  lpImageName, \
                  fUnicode, \
                  name ):
        """
        Constructor of the DllInfo class.
        """
        self.hFile                 = hFile
        self.baseAddress           = baseAddress
        self.dwDebugInfoFileOffset = dwDebugInfoFileOffset
        self.lpImageName           = lpImageName
        self.fUnicode              = fUnicode
        self.name                  = name

