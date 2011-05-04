
from distutils.core import setup
setup(
	name = 'NativDebugging',
	version = '1.0',
	description = 'Debugging tools for many platforms',
	author = 'Assaf Nativ',
	author_email = 'Nativ.Assaf@gmail.com',
	packages = ['NativDebugging', 'NativDebugging/Win32'],
    package_dir = {'NativDebugging' : 'src', 'NativDebugging/Win32' : 'src/Win32'},
	data_files = [('Lib\\\site-packages', ('NativDebugging.pth',))]
	)


