#
#   DllInfo.py
#
#   Dll description container
#   https://github.com/assafnativ/NativDebugging
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2019  Assaf Nativ

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
File name:      DllInfo.py
Define a class that contains all the information aboud a loaded dll.
Author: Assaf Nativ
"""

import os

class DllInfo:
    def __init__( self, \
                  hFile, \
                  baseAddress, \
                  dwDebugInfoFileOffset, \
                  lpImageName, \
                  name ):
        """
        Constructor of the DllInfo class.
        """
        self.hFile                 = hFile
        self.baseAddress           = baseAddress
        self.dwDebugInfoFileOffset = dwDebugInfoFileOffset
        self.lpImageName           = lpImageName
        self.name                  = name
        self.baseName              = os.path.basename(name)

