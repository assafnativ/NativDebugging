#
#   BreakPoint.py
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
File name:	BreakPoint.py
Define a class that represent a break point.
Author:	Assaf
Last date: 
	18.03.05
"""

# Consts
# Break points
BREAK_POINT_HIDE		= 2
BREAK_POINT_ACTIVE		= 1
BREAK_POINT_DEACTIVE	= 0		# Canceld, use ~BREAK_POINT_ACTIVE
BREAK_POINT_BYTE =	ord('\xcc')

class BreakPoint:
	def __init__( self, \
			address = -1, \
			state = BREAK_POINT_DEACTIVE, \
			original_byte = None, \
			proc = None ):
		""" 
		Constructor of the BreakPoint class.
		"""
		self.address =		address
		self.state =		state
		self.original_byte =	original_byte
		self.proc = 		proc
		
		
