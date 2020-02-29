# python setup.py bdist_wheel
# python -m twine upload dist/*

import sys

additional_requirements = []
if sys.platform.lower().startswith('win'):
    packagesNames = ['NativDebugging', 'NativDebugging/Win32']
    packagesDirs = {'NativDebugging' : 'src', 'NativDebugging/Win32' : 'src/Win32'}
    ExtraDataFiles = [('NativDebugging\\Win32', (
        'src/Win32/memReaderAMD64.exe',
        'src/Win32/memReaderIa64.exe',
        'src/Win32/memReaderx86.exe',
        'src/Win32/pythonGateAMD64.dll',
        'src/Win32/pythonGatex86.dll',
        'src/Win32/Detoursx86.dll',
        'src/Win32/DetoursAMD64.dll'))]
    additional_requirements.append('pywin32')
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

if 'noqt' not in sys.argv and '-noqt' not in sys.argv:
    additional_requirements.append('QtWidgets')

from setuptools import setup
setup(
        name = 'NativDebugging',
        version = '38',
        description = 'Debugging tools for many platforms',
        author = 'Assaf Nativ',
        author_email = 'Nativ.Assaf@gmail.com',
        packages = packagesNames,
        package_dir = packagesDirs,
        install_requires = ['future', 'rpyc', 'distorm3'] + additional_requirements,
        url = 'https://github.com/assafnativ/NativDebugging',
        keywords = ['debugger', 'memory', 'patterns', 'research', 'lowlevel', 'native'],
        license = "LGPLv3",
        data_files = [('', ('NativDebugging.pth',))] + ExtraDataFiles)


