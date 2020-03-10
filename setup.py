# python setup.py bdist_wheel
# python -m twine upload dist/*

import sys

packagesDirs = {}
packagesDirs['NativDebugging'] = 'src'
packagesDirs['NativDebugging/Win32'] ='src/Win32'
packagesDirs['NativDebugging/Linux'] = 'src/Linux'
packagesDirs['NativDebugging/Unix'] = 'src/Unix'
packagesDirs['NativDebugging/File'] = 'src/File'
packagesDirs['NativDebugging/MemoryDump'] = 'src/MemoryDump'
packagesDirs['NativDebugging/Patterns'] = 'src/Patterns'
packagesNames = ['NativDebugging']
packagesNames.append('NativDebugging/Win32')
packagesNames.append('NativDebugging/Linux')
packagesNames.append('NativDebugging/Unix')
packagesNames.append('NativDebugging/File')
packagesNames.append('NativDebugging/MemoryDump')
packagesNames.append('NativDebugging/Patterns')
dataFiles = [('', ('NativDebugging.pth',))]
dataFiles.append(('NativDebugging\\Win32', (
    'src/Win32/memReaderAMD64.exe',
    'src/Win32/memReaderIa64.exe',
    'src/Win32/memReaderx86.exe',
    'src/Win32/pythonGateAMD64.dll',
    'src/Win32/pythonGatex86.dll',
    'src/Win32/Detoursx86.dll',
    'src/Win32/DetoursAMD64.dll')))
requires = [
        'future',
        'rpyc',
        'distorm3',
        "pywin32;platform_system=='Windows'",
        'QtWidgets']

from setuptools import setup
setup(
        name = 'NativDebugging',
        version = '39',
        description = 'Debugging tools for many platforms',
        author = 'Assaf Nativ',
        author_email = 'Nativ.Assaf@gmail.com',
        packages = packagesNames,
        package_dir = packagesDirs,
        install_requires = requires,
        url = 'https://github.com/assafnativ/NativDebugging',
        keywords = ['debugger', 'memory', 'patterns', 'research', 'lowlevel', 'native'],
        license = "LGPLv3",
        data_files = dataFiles)


