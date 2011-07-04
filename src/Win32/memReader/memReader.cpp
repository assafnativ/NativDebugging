#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

using  namespace std;

#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif
#ifndef INTOUT
#define INOUT
#endif

#define RETURN_CODE_READ_SECCUESS		(0)
#define RETURN_CODE_ADDRESS_VALID		(0)
#define RETURN_CODE_ATTACH_OK			(0)
#define RETURN_CODE_WRONG_NUM_OF_ARGS	(2)
#define RETURN_CODE_INVALID_CMD_LINE	(3)
#define RETURN_CODE_ADDRESS_INVALID		(4)
#define RETURN_CODE_READ_FAILED			(5)
#define RETURN_CODE_ATTACH_FAILED		(6)

#define CMD_ARG_PROCESS_ID		(1)
#define CMD_NUM_OF_ARGS			(2)

typedef unsigned char * ADDR_TYPE;

/* Is wow64 */
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
static HANDLE g_processHandle = 0;
static BOOL isWow64 = FALSE;

/* Functions declurations */
int isAddressValid( IN ADDR_TYPE address );
int attachProcess( IN DWORD processId, OUT HANDLE * processHandle );
void detachProcess( IN HANDLE process );
int readAndPrint( IN ADDR_TYPE address, IN unsigned int size );

int main(int argc, char **argv)
{
    int returnCode = RETURN_CODE_READ_SECCUESS;

    unsigned char * address = NULL;
    unsigned int	size = 0;
    int				processId;

    /* Validate command line */
    /* Set the error code in case we faille here */
    returnCode = RETURN_CODE_WRONG_NUM_OF_ARGS;
    if( CMD_NUM_OF_ARGS != argc )
    {
        goto ERROR_INVALID_CMDLINE;
    }
    returnCode = RETURN_CODE_INVALID_CMD_LINE;
    sscanf_s( argv[CMD_ARG_PROCESS_ID], "%u", &processId );
    if( 0 == processId )
    {
        goto ERROR_INVALID_CMDLINE;
    }

    /* Reading memory 
    * 1. Attach the shared memory 
    * 2. Read and print the desired memory */
    returnCode = attachProcess(processId, &g_processHandle);
    if( RETURN_CODE_ATTACH_OK != returnCode )
    {
        goto ERROR_ATTACH_MEMORY_FAILED;
    }

    for( ;; )
    {
        scanf_s("%I64x %x", &address, &size);
        if( (NULL == address) &&
            (0 == size) )
        {
            break;
        }
        else if( (RETURN_CODE_ADDRESS_VALID != isAddressValid(address)) ||	(0 == size) )
        {
            cout << "Invalid address or size" << endl;
            continue;
        }
        returnCode = readAndPrint(address, size);
        if( RETURN_CODE_READ_SECCUESS != returnCode )
        {
            cout << "Invalid read" << endl;
        }
    }


    /* Cleanup and return */
    detachProcess(g_processHandle);
ERROR_ATTACH_MEMORY_FAILED:
ERROR_INVALID_CMDLINE:
    return returnCode;
}

int isAddressValid( IN ADDR_TYPE address )
{
#pragma warning( disable : 4312 )    /* address is machine depended, but the warning is not */
#ifdef WIN64
    /* For Itanium it's 0x6fbfffeffff, but it sounds too much for me, so I choose to leave it as it is */
    if( (ADDR_TYPE)(0x000007fffffeffff) <= address || (ADDR_TYPE)(0x10000) > address) {
        //#ifdef _DEBUG
        //		DebugBreak();
        //#endif
        return RETURN_CODE_ADDRESS_INVALID;
    }
#else
    if( isWow64 ) {
        if( (ADDR_TYPE)(0x10000) > address ) {
            return RETURN_CODE_ADDRESS_INVALID;
        }
    } else {
        if( (ADDR_TYPE)(0xc0000000) <= address || (ADDR_TYPE)(0x10000) > address ) {
            //#ifdef _DEBUG
            //		DebugBreak();
            //#endif
            return RETURN_CODE_ADDRESS_INVALID;
        }
    }
#endif
#pragma warning( default : 4312 )    /* address is machine depended, but the warning is not */
    return RETURN_CODE_ADDRESS_VALID;
}

int attachProcess( IN DWORD processId, OUT HANDLE * processHandle )
{    
    TOKEN_PRIVILEGES privileges;
    HANDLE accessToken;

    /* Adjust debug privileges */
    OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &accessToken );
    LookupPrivilegeValueA( NULL, "SeDebugPrivilege", &privileges.Privileges[0].Luid );
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = 2;
    if( FALSE == AdjustTokenPrivileges(  accessToken, FALSE, &privileges, 0, NULL, NULL ) ) {
        cout << "Unable to adjust debug privileges, but we would try to connect anyway" << endl;
    }
    CloseHandle( accessToken );

    /* Attach */
    *processHandle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, TRUE, processId );
    if( NULL == processHandle ) {
        return( RETURN_CODE_ATTACH_FAILED );
    }

    /* Check for Wow64 */
    LPFN_ISWOW64PROCESS 
        fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),
        "IsWow64Process");
    if( NULL != fnIsWow64Process ) {
        fnIsWow64Process(*processHandle, &isWow64);
    } else {
        isWow64 = FALSE;
    }

    return( RETURN_CODE_ATTACH_OK );
}

void detachProcess( IN HANDLE processHandle )
{
    CloseHandle(processHandle);
    return;
}

int readAndPrint( IN ADDR_TYPE address, IN unsigned int size )
{
    static DWORD pos;
    static char temp_cout[10];
    static BYTE memDump[4];
    static SIZE_T bytesRead;
    static BOOL readFuncResult;

    for( pos = 0; pos < size; ++pos )
    {
        readFuncResult = ReadProcessMemory(
                            g_processHandle,
                            address + pos,
                            memDump,
                            (SIZE_T)1,
                            &bytesRead );
        if( (FALSE == readFuncResult) || 
            (1 != bytesRead) ) {

            return RETURN_CODE_ADDRESS_INVALID;
        }
        sprintf_s(temp_cout, 10, "%02x", memDump[0]);
        cout << temp_cout;
    }
    cout << endl;
    return RETURN_CODE_READ_SECCUESS;
}