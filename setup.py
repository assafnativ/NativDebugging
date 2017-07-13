
import sys
if sys.platform.lower().startswith('win'):
    packagesNames = ['NativDebugging', 'NativDebugging/Win32']
    packagesDirs = {'NativDebugging' : 'src', 'NativDebugging/Win32' : 'src/Win32'}
    ExtraDataFiles = [('Lib\\site-packages\\NativDebugging\\Win32', (
        'src/Win32/memReaderAMD64.exe',
        'src/Win32/memReaderIa64.exe',
        'src/Win32/memReaderx86.exe'))]
else:
    packagesNames = ['NativDebugging', 'NativDebugging/Linux', 'NativDebugging/Unix']
    packagesDirs = { \
            'NativDebugging' : 'src', \
            'NativDebugging/Linux' : 'src/Linux',\
            'NativDebugging/Unix' : 'src/Unix'}
    ExtraDataFiles = []
packagesNames.append('NativDebugging/File')
packagesNames.append('NativDebugging/MemoryDump')
packagesNames.append('NativDebugging/Patterns')
packagesDirs['NativDebugging/File'] = 'src/File'
packagesDirs['NativDebugging/MemoryDump'] = 'src/MemoryDump'
packagesDirs['NativDebugging/Patterns'] = 'src/Patterns'

from distutils.core import setup
setup(
        name = 'NativDebugging',
        version = '30',
        description = 'Debugging tools for many platforms',
        author = 'Assaf Nativ',
        author_email = 'Nativ.Assaf@gmail.com',
        packages = packagesNames,
        package_dir = packagesDirs,
        url = 'https://github.com/assafnativ/NativDebugging',
        keywords = ['debugger', 'memory', 'patterns', 'research', 'lowlevel', 'native'],
        license = "LGPLv3",
        data_files = [('Lib\\\site-packages', ('NativDebugging.pth',))] + ExtraDataFiles)


