
import sys
if sys.platform.lower().startswith('win'):
    packagesNames = ['NativDebugging', 'NativDebugging/Win32']
    packagesDirs = {'NativDebugging' : 'src', 'NativDebugging/Win32' : 'src/Win32'}
    ExtraDataFiles = [('Lib\\site-packages\\NativDebugging\\Win32', (
        'src/Win32/memReaderAMD64.exe', 
        'src/Win32/memReaderIa64.exe', 
        'src/Win32/memReaderx86.exe'))]
elif sys.platform.lower().startswith('linux'):
    packagesNames = ['NativDebugging', 'NativDebugging/Linux']
    packagesDirs = {'NativDebugging' : 'src', 'NativDebugging/Linux' : 'src/Linux'}
    ExtraDataFiles = []
else:
    packagesNames = ['NativDebugging', 'NativDebugging/Unix']
    packagesDirs = {'NativDebugging' : 'src', 'NativDebugging/Unix' : 'src/Unix'}
    ExtraDataFiles = [ ('Lib\\site-packages\\NativDebugging\\Unix', ('src/Unix/memReader')) ]

from distutils.core import setup
setup(
	name = 'NativDebugging',
	version = '1.0',
	description = 'Debugging tools for many platforms',
	author = 'Assaf Nativ',
	author_email = 'Nativ.Assaf@gmail.com',
	packages = packagesNames,
    package_dir = packagesDirs,
	data_files = [('Lib\\\site-packages', ('NativDebugging.pth',))] + ExtraDataFiles
	)


