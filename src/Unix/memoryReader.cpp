#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <ctype.h>

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

#define CMD_ARG_SHMID			(1)
#define CMD_ARG_BASE			(2)
#define CMD_ARG_SHARED_MEM_SIZE	(3)
#define CMD_NUM_OF_ARGS			(4)

/* Functions declurations */
int isAddressValid( IN void * address, IN void * base, IN unsigned long sharedMemSize );
int attachMemory( IN int shmid, OUT void ** sharedMem );
void detachMemmory( IN void * sharedMem );
int readAndPrint( IN unsigned char * address, IN unsigned int size, IN unsigned char * sharedMem, IN unsigned char * base );

int main(int argc, char **argv)
{
	int returnCode = RETURN_CODE_READ_SECCUESS;

	unsigned char * address = NULL;
	unsigned int	size = 0;
	int				shmid;
	unsigned char * base;
	unsigned char * sharedMem;
	unsigned long	sharedMemSize;

	/* Validate command line */
	/* Set the error code in case we faile here */
	returnCode = RETURN_CODE_WRONG_NUM_OF_ARGS;
	if( CMD_NUM_OF_ARGS != argc )
	{
		goto ERROR_INVALID_COMMAND_LINE;
	}
	returnCode = RETURN_CODE_INVALID_CMD_LINE;
	sscanf( argv[CMD_ARG_SHMID],			"%u",	&shmid );
	sscanf( argv[CMD_ARG_BASE],				"%lx",	&base );
	sscanf( argv[CMD_ARG_SHARED_MEM_SIZE],	"%lx", 	&sharedMemSize );
	if( 	(0 == shmid) ||
			(0 == sharedMemSize) )
	{
		goto ERROR_INVALID_COMMAND_LINE;
	}

	/* Reading memory 
	 * 1. Attach the shared memory 
	 * 2. Read and print the desired memory */
	returnCode = attachMemory(shmid, (void **)&sharedMem);
	if( RETURN_CODE_ATTACH_OK != returnCode )
	{
		goto ERROR_ATTACH_MEMORY_FAILED;
	}

	for( ;; )
	{
		scanf("%lx %x", &address, &size);
		if( (NULL == address) &&
			(0 == size) )
		{
			break;
		}
		else if( (RETURN_CODE_ADDRESS_VALID != isAddressValid(address, base, sharedMemSize)) ||	(0 == size) )
		{
			cout << "Invliad address or size" << endl;
			continue;
		}
		returnCode = readAndPrint(address, size, sharedMem, base);
		if( RETURN_CODE_READ_SECCUESS != returnCode )
		{
			cout << "Invalid read" << endl;
		}
	}


	/* Cleanup and return */
	detachMemmory(sharedMem);
ERROR_ATTACH_MEMORY_FAILED:
ERROR_INVALID_COMMAND_LINE:
	return returnCode;
}

int isAddressValid( IN void * address, IN void * base, IN unsigned long sharedMemSize )
{
	if( (((unsigned long long)address) > (((unsigned long long)base) + sharedMemSize)) ||
		(((unsigned long long)address) < ((unsigned long long)base)) )
	{
		return RETURN_CODE_ADDRESS_INVALID;
	}
	return RETURN_CODE_ADDRESS_VALID;
}

int attachMemory( IN int shmid, OUT void ** sharedMem )
{
	*sharedMem = shmat(shmid, 0, SHM_RDONLY);
	if( -1 == *((long long *)sharedMem) )
	{
		return RETURN_CODE_ATTACH_FAILED;
	}
	return RETURN_CODE_ATTACH_OK;
}

void detachMemmory( IN void * sharedMem )
{
	shmdt( (char*)sharedMem );
	return;
}

int readAndPrint( IN unsigned char * address, IN unsigned int size, IN unsigned char * sharedMem, IN unsigned char * base )
{
	unsigned int pos;
	char temp_cout[10];

	for( pos = 0; pos < size; ++pos )
	{
		sprintf(temp_cout, "%02x", *(address + (sharedMem - base) + pos));
		cout << temp_cout;
	}
	cout << endl;
	return RETURN_CODE_READ_SECCUESS;
}
