#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include "common/common.h"
#include "main.h"
#include "dynamic_libs/socket_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "kernel/syscalls.h"
#include "dynamic_libs/fs_functions.h"
#include "common/fs_defs.h"
#include "system/exception_handler.h"

void *client;
void *commandBlock;
void *disassemblerBuffer;

struct pygecko_bss_t {
	int error, line;
	void *thread;
	unsigned char stack[0x6F00];
};

#define CHECK_ERROR(cond) if (cond) { bss->line = __LINE__; goto error; }
#define errno (*__gh_errno_ptr())
#define MSG_DONTWAIT 32
#define EWOULDBLOCK 6
#define FS_BUFFER_SIZE 0x1000
#define DATA_BUFFER_SIZE 0x5000

#define ASSERT_VALID_BUFFER_SIZE(maximum, actual, message) \
if(actual > maximum) { \
    char buffer[100] = {0}; \
    __os_snprintf(buffer, 100, "%s: (maximum: %i, actual: %i)", message, maximum, actual); \
    OSFatal(buffer); \
} \

#define CHECK_FUNCTION_FAILED(returnValue, functionName) \
    if (returnValue < 0) { \
        char buffer[100] = {0}; \
        __os_snprintf(buffer, 100, "%s failed with return value: %i", functionName, returnValue); \
        OSFatal(buffer); \
    } \

#define ASSERT_VALID_ADDRESS(address, message) \
    if(!OSIsAddressValid((void *) address)) { \
    char buffer[100] = {0}; \
        __os_snprintf(buffer, 100, "Address %04x invalid: %s", address, message); \
        OSFatal(buffer); \
    } \

#define ASSERT_INTEGER(actual, expected, name) \
    if(actual != expected) { \
        char buffer[50] = {0}; \
        __os_snprintf(buffer, 50, "%s assertion failed: %i == %i", name, actual, expected); \
        OSFatal(buffer); \
    } \

#define ASSERT_STRING(actual, expected) \
    if(strcmp(actual, expected) != 0) { \
        char buffer[50] = {0}; \
        __os_snprintf(buffer, 50, "String assertion failed: \"%s\" == \"%s\"", actual, expected); \
        OSFatal(buffer); \
    } \

#define CHECK_ALLOCATED(variable, name) \
    if(variable == 0) { \
        char buffer[50] = {0}; \
        __os_snprintf(buffer, 50, "%s allocation failed", name); \
        OSFatal(buffer); \
    } \


/*Validates the address range (last address inclusive) but is SLOW on bigger ranges */
static int validateAddressRange(int starting_address, int ending_address) {
	return __OSValidateAddressSpaceRange(1, (void *) starting_address, ending_address - starting_address + 1);
}

unsigned char *memcpy_buffer[DATA_BUFFER_SIZE];

void pygecko_memcpy(unsigned char *destinationBuffer, unsigned char *sourceBuffer, unsigned int length) {
	memcpy(memcpy_buffer, sourceBuffer, length);
	SC0x25_KernelCopyData((unsigned int) OSEffectiveToPhysical(destinationBuffer), (unsigned int) &memcpy_buffer,
						  length);
	DCFlushRange(destinationBuffer, (u32) length);
}

static int recvwait(struct pygecko_bss_t *bss, int sock, void *buffer, int len) {
	int ret;
	while (len > 0) {
		ret = recv(sock, buffer, len, 0);
		CHECK_ERROR(ret < 0);
		len -= ret;
		buffer += ret;
	}
	return 0;

	error:
	bss->error = ret;
	return ret;
}

static int recvbyte(struct pygecko_bss_t *bss, int sock) {
	unsigned char buffer[1];
	int ret;

	ret = recvwait(bss, sock, buffer, 1);
	if (ret < 0) return ret;
	return buffer[0];
}

static int checkbyte(int sock) {
	unsigned char buffer[1];
	int ret;

	ret = recv(sock, buffer, 1, MSG_DONTWAIT);
	if (ret < 0) return ret;
	if (ret == 0) return -1;
	return buffer[0];
}

static int sendwait(struct pygecko_bss_t *bss, int sock, const void *buffer, int len) {
	int ret;
	while (len > 0) {
		ret = send(sock, buffer, len, 0);
		CHECK_ERROR(ret < 0);
		len -= ret;
		buffer += ret;
	}
	return 0;
	error:
	bss->error = ret;
	return ret;
}

static int sendbyte(struct pygecko_bss_t *bss, int sock, unsigned char byte) {
	unsigned char buffer[1];

	buffer[0] = byte;
	return sendwait(bss, sock, buffer, 1);
}

void writeScreen(const char *message) {
	for (unsigned int bufferIndex = 0; bufferIndex < 2; bufferIndex++) {
		OSScreenClearBufferEx(bufferIndex, 0);
		OSScreenPutFontEx(bufferIndex, 0, 0, message);
		OSScreenFlipBuffersEx(bufferIndex);
	}
}

void receiveString(struct pygecko_bss_t *bss, int clientfd, char *stringBuffer, int bufferSize) {
	// Receive the string length
	char buffer[4] = {0};
	int ret = recvwait(bss, clientfd, buffer, 4);
	CHECK_FUNCTION_FAILED(ret, "recvwait (string length)")
	int stringLength = ((int *) buffer)[0];

	if (stringLength >= 0 && stringLength <= bufferSize) {
		// Receive the actual string
		ret = recvwait(bss, clientfd, stringBuffer, stringLength);
		CHECK_FUNCTION_FAILED(ret, "recvwait (string)")
	} else {
		OSFatal("String buffer size exceeded");
	}
}

void considerInitializingFileSystem() {
	if (!client) {
		// Initialize the file system
		int status = FSInit();
		CHECK_FUNCTION_FAILED(status, "FSInit")

		// Allocate the client
		client = malloc(FS_CLIENT_SIZE);
		CHECK_ALLOCATED(client, "Client")

		// Register the client
		status = FSAddClientEx(client, 0, -1);
		CHECK_FUNCTION_FAILED(status, "FSAddClientEx")

		// Allocate the command block
		commandBlock = malloc(FS_CMD_BLOCK_SIZE);
		CHECK_ALLOCATED(commandBlock, "Command block")

		FSInitCmdBlock(commandBlock);
	}
}

void formatDisassembled(char *format, ...) {
	int length = 200;
	disassemblerBuffer = malloc(length);
	__os_snprintf((char *) disassemblerBuffer, length, format);
}

static int rungecko(struct pygecko_bss_t *bss, int clientfd) {
	int ret;

	// Hold the command and the data
	unsigned char buffer[1 + DATA_BUFFER_SIZE];

	// Run the RPC server
	while (1) {
		ret = checkbyte(clientfd);

		if (ret < 0) {
			CHECK_ERROR(errno != EWOULDBLOCK);
			GX2WaitForVsync();
			continue;
		}

		switch (ret) {
			case 0x01: { /* cmd_poke08 */
				char *ptr;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				ptr = ((char **) buffer)[0];
				*ptr = buffer[7];
				DCFlushRange(ptr, 1);
				break;
			}
			case 0x02: { /* cmd_poke16 */
				short *ptr;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				ptr = ((short **) buffer)[0];
				*ptr = ((short *) buffer)[3];
				DCFlushRange(ptr, 2);
				break;
			}
			case 0x03: { /* cmd_pokemem */
				int destination_address, value;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				destination_address = ((int *) buffer)[0];
				value = ((int *) buffer)[1];
				pygecko_memcpy((unsigned char *) destination_address, (unsigned char *) &value, 4);
				break;
			}
			case 0x04: { /* cmd_readmem */
				const unsigned char *startingAddress, *endingAddress;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)
				startingAddress = ((const unsigned char **) buffer)[0];
				endingAddress = ((const unsigned char **) buffer)[1];

				while (startingAddress != endingAddress) {

					int length = (int) (endingAddress - startingAddress);
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					int rangeIterationIndex = 0;
					for (; rangeIterationIndex < length; rangeIterationIndex++) {
						if (startingAddress[rangeIterationIndex] != 0) {
							break;
						}
					}

					if (rangeIterationIndex == length) {
						// All read bytes are zero so we won't send the read bytes
						ret = sendbyte(bss, clientfd, 0xB0);
						CHECK_ERROR(ret < 0)
					} else {
						// TODO Compression of ptr, sending of status, compressed size and data, length: 1 + 4 + len(data)
						buffer[0] = 0xBD;
						memcpy(buffer + 1, startingAddress, length);
						ret = sendwait(bss, clientfd, buffer, length + 1);
						CHECK_ERROR(ret < 0)
					}

					/* 	No exit condition.
						We reconnect client-sided instead as a hacky work-around
						 to gain a little more performance by avoiding the very rare search canceling
					 */

					startingAddress += length;
				}
				break;
			}
			case 0x05: { /* cmd_validate_address */

				// Receive the address
				ret = recvwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);

				// Make the address pointer
				void *address_pointer = ((void **) buffer)[0];

				// Validate
				int is_address_valid = OSIsAddressValid(address_pointer);

				// Send the result
				sendbyte(bss, clientfd, (unsigned char) is_address_valid);
				break;
			}
			case 0x06: { /* cmd_validate_address_range */
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				// Retrieve the data
				int starting_address = ((int *) buffer)[0];
				int ending_address = ((int *) buffer)[1];

				int is_address_range_valid = validateAddressRange(starting_address, ending_address);

				sendbyte(bss, clientfd, (unsigned char) is_address_range_valid);
				break;
			}
			case 0x07: { /* cmd_memory_disassemble */
				// Receive the starting, ending address and the disassembler options
				ret = recvwait(bss, clientfd, buffer, 4 + 4 + 4);
				CHECK_ERROR(ret < 0)
				void *startingAddress = ((void **) buffer)[0];
				void *endingAddress = ((void **) buffer)[1];
				int disassemblerOptions = ((int *) buffer)[2];

				// Disassemble
				DisassemblePPCRange(startingAddress, endingAddress, formatDisassembled, OSGetSymbolName,
									(u32) disassemblerOptions);

				// Send the disassembler buffer length
				int length = strlen(disassemblerBuffer);
				ret = sendwait(bss, clientfd, &length, 4);
				CHECK_FUNCTION_FAILED(ret, "sendwait (disassembler buffer size)")

				// Send the disassembled data
				ret = sendwait(bss, clientfd, disassemblerBuffer, length);
				CHECK_FUNCTION_FAILED(ret, "sendwait (disassembler buffer)")

				break;
			}
			case 0x0b: { /* cmd_writekern */
				void *ptr, *value;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				ptr = ((void **) buffer)[0];
				value = ((void **) buffer)[1];

				kern_write(ptr, (uint32_t) value);
				break;
			}
			case 0x0c: { /* cmd_readkern */
				void *ptr, *value;
				ret = recvwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);

				ptr = ((void **) buffer)[0];

				value = (void *) kern_read(ptr);

				*(void **) buffer = value;
				sendwait(bss, clientfd, buffer, 4);
				break;
			}
			case 0x41: { /* cmd_upload */
				// Receive the starting and ending addresses
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);
				unsigned char *current_address = ((unsigned char **) buffer)[0];
				unsigned char *end_address = ((unsigned char **) buffer)[1];

				while (current_address != end_address) {
					int length;

					length = (int) (end_address - current_address);
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					ret = recvwait(bss, clientfd, buffer, length);
					CHECK_ERROR(ret < 0)
					pygecko_memcpy(current_address, buffer, (unsigned int) length);

					current_address += length;
				}

				sendbyte(bss, clientfd, 0xaa); /* GCACK */
				break;
			}
			case 0x50: { /* cmd_status */
				ret = sendbyte(bss, clientfd, 1); /* running */
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x51: { /* cmd_data_buffer_size */
				((int *) buffer)[0] = DATA_BUFFER_SIZE;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x52: { /* cmd_read_file */
				char file_path[FS_MAX_FULLPATH_SIZE] = {0};
				receiveString(bss, clientfd, file_path, FS_MAX_FULLPATH_SIZE);

				considerInitializingFileSystem();

				int handle;
				int status = FSOpenFile(client, commandBlock, file_path, "r", &handle, FS_RET_ALL_ERROR);

				if (status == FS_STATUS_OK) {
					// Send the OK status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (OK status)")

					// Retrieve the file statistics
					FSStat stat;
					ret = FSGetStatFile(client, commandBlock, handle, &stat, FS_RET_ALL_ERROR);
					CHECK_FUNCTION_FAILED(ret, "FSGetStatFile")

					// Send the total bytes count
					int totalBytes = (int) stat.size;
					((int *) buffer)[0] = totalBytes;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (total bytes)")

					// Allocate the file bytes buffer
					unsigned int file_buffer_size = 0x2000;
					char *fileBuffer = (char *) OSAllocFromSystem(file_buffer_size, FS_IO_BUFFER_ALIGN);
					CHECK_ALLOCATED(fileBuffer, "File buffer")

					int totalBytesRead = 0;
					while (totalBytesRead < totalBytes) {
						int bytesRead = FSReadFile(client, commandBlock, fileBuffer, 1, file_buffer_size,
												   handle, 0, FS_RET_ALL_ERROR);
						CHECK_FUNCTION_FAILED(bytesRead, "FSReadFile")

						// Send file bytes
						ret = sendwait(bss, clientfd, fileBuffer, bytesRead);
						CHECK_FUNCTION_FAILED(ret, "sendwait (file buffer)")

						totalBytesRead += bytesRead;
					}

					ret = FSCloseFile(client, commandBlock, handle, FS_RET_ALL_ERROR);
					CHECK_FUNCTION_FAILED(ret, "FSCloseFile")

					OSFreeToSystem(fileBuffer);
				} else {
					// Send the error status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (error status)")
				}

				break;
			}
			case 0x53: { /* cmd_read_directory */
				char directory_path[FS_MAX_FULLPATH_SIZE] = {0};
				receiveString(bss, clientfd, directory_path, FS_MAX_FULLPATH_SIZE);

				considerInitializingFileSystem();

				int handle;
				FSDirEntry entry;

				ret = FSOpenDir(client, commandBlock, directory_path, &handle, FS_RET_ALL_ERROR);

				if (ret == FS_STATUS_OK) {
					// Send the success status
					((int *) buffer)[0] = ret;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (success status)")

					int entrySize = sizeof(FSDirEntry);

					// Read every entry in the given directory
					while (FSReadDir(client, commandBlock, handle, &entry, -1) == FS_STATUS_OK) {
						// Let the client know how much data is going to be sent (even though this is constant)
						((int *) buffer)[0] = entrySize;
						ret = sendwait(bss, clientfd, buffer, 4);
						CHECK_FUNCTION_FAILED(ret, "sendwait (data coming)")

						// Send the struct
						ret = sendwait(bss, clientfd, &entry, entrySize);
						CHECK_FUNCTION_FAILED(ret, "sendwait (directory entry)")
					}

					// No more data will be sent, hence a 0 byte
					((int *) buffer)[0] = 0;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (no more data)")

					// Done, close the directory also
					ret = FSCloseDir(client, commandBlock, handle, FS_RET_ALL_ERROR);
					CHECK_FUNCTION_FAILED(ret, "FSCloseDir")
				} else {
					// Send the status
					((int *) buffer)[0] = ret;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (error status)")
				}

				break;
			}
			case 0x54: { /* cmd_replace_file */
				// TODO Write file

				// Receive the file path
				char file_path[FS_MAX_FULLPATH_SIZE] = {0};
				receiveString(bss, clientfd, file_path, FS_MAX_FULLPATH_SIZE);

				considerInitializingFileSystem();

				// Create an empty file for writing. Its contents will be erased
				int handle;
				int status = FSOpenFile(client, commandBlock, file_path, "w", &handle, FS_RET_ALL_ERROR);

				if (status == FS_STATUS_OK) {
					// Send the OK status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (OK status)")

					// Set the file handle position to the beginning
					ret = FSSetPosFile(client, commandBlock, handle, 0, FS_RET_ALL_ERROR);
					CHECK_FUNCTION_FAILED(ret, "FSSetPosFile")

					// Allocate the file bytes buffer
					unsigned int file_buffer_size = 0x2000;
					char *fileBuffer = (char *) OSAllocFromSystem(file_buffer_size, FS_IO_BUFFER_ALIGN);
					CHECK_ALLOCATED(fileBuffer, "File buffer")

					// Send the maximum file buffer size
					ret = sendwait(bss, clientfd, &file_buffer_size, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (maximum file buffer size)")

					while (true) {
						// Receive the data bytes length
						unsigned int dataLength;
						ret = recvwait(bss, clientfd, &dataLength, 4);
						CHECK_FUNCTION_FAILED(ret, "recvwait (File bytes length)")
						ASSERT_VALID_BUFFER_SIZE(file_buffer_size, dataLength, "File buffer overrun attempted")

						if (dataLength > 0) {
							// Receive the data
							ret = recvwait(bss, clientfd, fileBuffer, dataLength);
							CHECK_FUNCTION_FAILED(ret, "recvwait (File buffer)")

							// Write the data and advance file handle position
							ret = FSWriteFile(client, commandBlock, fileBuffer, 1,
											  dataLength, handle, 0, FS_RET_ALL_ERROR);
							CHECK_FUNCTION_FAILED(ret, "FSWriteFile")
						} else {
							// Done
							break;
						}
					}

					/*// Flush the file back
					ret = FSFlushFile(client, commandBlock, handle, FS_RET_ALL_ERROR);
					CHECK_FUNCTION_FAILED(ret, "FSFlushFile")*/

					// Close the file
					ret = FSCloseFile(client, commandBlock, handle, FS_RET_ALL_ERROR);
					CHECK_FUNCTION_FAILED(ret, "FSCloseFile")

					// Free the file buffer
					OSFreeToSystem(fileBuffer);
				} else {
					// Send the status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					CHECK_FUNCTION_FAILED(ret, "sendwait (status)")
				}

				break;
			}
			case 0x55: { /* cmd_code_handler_install_address */
				((int *) buffer)[0] = CODE_HANDLER_INSTALL_ADDRESS;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0)

				break;
			}
			case 0x56: { /* read_threads */
				int OS_THREAD_SIZE = 0x6A0;

				int currentThreadAddress = OSGetCurrentThread();
				ASSERT_VALID_ADDRESS(currentThreadAddress, "OSGetCurrentThread")
				int iterationThreadAddress = currentThreadAddress;
				int temporaryThreadAddress;

				// Follow "previous thread" pointers back to the beginning
				while ((temporaryThreadAddress = *(int *) (iterationThreadAddress + 0x390)) != 0) {
					iterationThreadAddress = temporaryThreadAddress;
					ASSERT_VALID_ADDRESS(iterationThreadAddress, "iterationThreadAddress going backwards")
				}

				// Send all threads by following the "next thread" pointers
				while ((temporaryThreadAddress = *(int *) (iterationThreadAddress + 0x38C)) != 0) {
					// Send the starting thread's address
					((int *) buffer)[0] = iterationThreadAddress;

					// Send the thread struct itself
					memcpy(buffer + 4, (void *) iterationThreadAddress, OS_THREAD_SIZE);
					ret = sendwait(bss, clientfd, buffer, 4 + OS_THREAD_SIZE);
					CHECK_ERROR(ret < 0)

					iterationThreadAddress = temporaryThreadAddress;
					ASSERT_VALID_ADDRESS(iterationThreadAddress, "iterationThreadAddress going forwards")
				}

				// The previous while would skip the last thread so send it also
				((int *) buffer)[0] = iterationThreadAddress;
				memcpy(buffer + 4, (void *) iterationThreadAddress, OS_THREAD_SIZE);
				ret = sendwait(bss, clientfd, buffer, 4 + OS_THREAD_SIZE);
				CHECK_ERROR(ret < 0)

				// Let the client know that no more threads are coming
				((int *) buffer)[0] = 0;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0)

				break;
			}
			case 0x57 : {
				// TODO Get persistent ID
				/*else if (cmd == 17) { //Get persistent id
				a->nn_act_Initialize();
				u8 slot = a->nn_act_GetSlotNo();
				u32 persistentId = a->nn_act_GetPersistentIdEx(slot);
				sendall(client, &persistentId, 4);
				a->nn_act_Finalize();
			}*/
				break;
			}
			case 0x58: {
				// TODO Write screen
			}
			case 0x60: { /* cmd_follow_pointer */
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				// Retrieve the pointer address and amount of offsets
				int baseAddress = ((int *) buffer)[0];
				int offsetsCount = ((int *) buffer)[1];

				// Receive the offsets
				ret = recvwait(bss, clientfd, buffer, offsetsCount * 4);
				CHECK_ERROR(ret < 0);
				int *offsets = (int *) buffer;

				int destinationAddress = baseAddress;

				// Apply pointer offsets
				for (int offsetIndex = 0; offsetIndex < offsetsCount; offsetIndex++) {
					int pointerValue = *(int *) destinationAddress;
					int offset = offsets[offsetIndex];
					destinationAddress = pointerValue + offset;

					// Validate the pointer address
					bool isValidDestinationAddress = OSIsAddressValid((const void *) destinationAddress)
													 && destinationAddress >= 0x10000000
													 && destinationAddress < 0x50000000;

					// Bail out if invalid
					if (!isValidDestinationAddress) {
						destinationAddress = -1;

						break;
					}
				}

				// Return the destination address
				((int *) buffer)[0] = destinationAddress;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);

				break;
			}
			case 0x70: { /* cmd_rpc */
				long long (*fun)(int, int, int, int, int, int, int, int);
				int r3, r4, r5, r6, r7, r8, r9, r10;
				long long result;

				ret = recvwait(bss, clientfd, buffer, 4 + 8 * 4);
				CHECK_ERROR(ret < 0);

				fun = ((void **) buffer)[0];
				r3 = ((int *) buffer)[1];
				r4 = ((int *) buffer)[2];
				r5 = ((int *) buffer)[3];
				r6 = ((int *) buffer)[4];
				r7 = ((int *) buffer)[5];
				r8 = ((int *) buffer)[6];
				r9 = ((int *) buffer)[7];
				r10 = ((int *) buffer)[8];

				result = fun(r3, r4, r5, r6, r7, r8, r9, r10);

				((long long *) buffer)[0] = result;
				ret = sendwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x71: { /* cmd_getsymbol */
				int size = recvbyte(bss, clientfd);
				CHECK_ERROR(size < 0);

				ret = recvwait(bss, clientfd, buffer, size);
				CHECK_ERROR(ret < 0);

				/* Identify the RPL name and symbol name */
				char *rplname = (char *) &((int *) buffer)[2];
				char *symname = (char *) (&buffer[0] + ((int *) buffer)[1]);

				/* Get the symbol and store it in the buffer */
				unsigned int module_handle, function_address;
				OSDynLoad_Acquire(rplname, &module_handle);

				char data = (char) recvbyte(bss, clientfd);
				OSDynLoad_FindExport(module_handle, data, symname, &function_address);

				((int *) buffer)[0] = (int) function_address;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x72: { /* cmd_search32 */
				ret = recvwait(bss, clientfd, buffer, 12);
				CHECK_ERROR(ret < 0);
				int addr = ((int *) buffer)[0];
				int val = ((int *) buffer)[1];
				int size = ((int *) buffer)[2];
				int i;
				int resaddr = 0;
				for (i = addr; i < (addr + size); i += 4) {
					if (*(int *) i == val) {
						resaddr = i;
						break;
					}
				}
				((int *) buffer)[0] = resaddr;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x80: { /* cmd_rpc_big */
				long long (*fun)(int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int);
				int r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18;
				long long result;

				ret = recvwait(bss, clientfd, buffer, 4 + 16 * 4);
				CHECK_ERROR(ret < 0);

				fun = ((void **) buffer)[0];
				r3 = ((int *) buffer)[1];
				r4 = ((int *) buffer)[2];
				r5 = ((int *) buffer)[3];
				r6 = ((int *) buffer)[4];
				r7 = ((int *) buffer)[5];
				r8 = ((int *) buffer)[6];
				r9 = ((int *) buffer)[7];
				r10 = ((int *) buffer)[8];
				r11 = ((int *) buffer)[9];
				r12 = ((int *) buffer)[10];
				r13 = ((int *) buffer)[11];
				r14 = ((int *) buffer)[12];
				r15 = ((int *) buffer)[13];
				r16 = ((int *) buffer)[14];
				r17 = ((int *) buffer)[15];
				r18 = ((int *) buffer)[16];

				result = fun(r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18);

				((long long *) buffer)[0] = result;
				ret = sendwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x99: { /* cmd_version */
				ret = sendbyte(bss, clientfd, 0x82); /* WiiU */
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0x9A: { /* cmd_os_version */
				((int *) buffer)[0] = (int) OS_FIRMWARE;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);
				break;
			}
			case 0xcc: { /* GCFAIL */
				break;
			}
			default:
				ret = -1;
				CHECK_ERROR(0);
				break;
		}
	}

	error:
	bss->error = ret;
	return 0;
}

static int start(int argc, void *argv) {
	int sockfd = -1, clientfd = -1, ret = 0, len;
	struct sockaddr_in addr;
	struct pygecko_bss_t *bss = argv;

	setup_os_exceptions();
	socket_lib_init();

	while (1) {
		addr.sin_family = AF_INET;
		addr.sin_port = 7331;
		addr.sin_addr.s_addr = 0;

		sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		CHECK_ERROR(sockfd == -1)

		ret = bind(sockfd, (void *) &addr, 16);
		CHECK_ERROR(ret < 0)

		ret = listen(sockfd, 20);
		CHECK_ERROR(ret < 0)

		while (1) {
			len = 16;
			clientfd = accept(sockfd, (void *) &addr, &len);
			CHECK_ERROR(clientfd == -1)
			ret = rungecko(bss, clientfd);
			CHECK_ERROR(ret < 0)
			socketclose(clientfd);
			clientfd = -1;
		}

		error:
		if (clientfd != -1)
			socketclose(clientfd);
		if (sockfd != -1)
			socketclose(sockfd);
		bss->error = ret;
	}

	return 0;
}

static int CCThread(int argc, void *argv) {
	struct pygecko_bss_t *bss;

	bss = memalign(0x40, sizeof(struct pygecko_bss_t));
	if (bss == 0)
		return 0;
	memset(bss, 0, sizeof(struct pygecko_bss_t));

	if (OSCreateThread(&bss->thread, start, 1, bss, (u32) bss->stack + sizeof(bss->stack), sizeof(bss->stack), 0,
					   0xc) == 1) {
		OSResumeThread(&bss->thread);
	} else {
		free(bss);
	}

	if (CCHandler == 1) {
		void (*entrypoint)() = (void *) CODE_HANDLER_INSTALL_ADDRESS;

		while (1) {
			usleep(9000);
			entrypoint();
		}
	}
	return 0;
}

void start_pygecko(void) {
	unsigned int stack = (unsigned int) memalign(0x40, 0x100);
	stack += 0x100;

	// Create the thread
	void *thread = memalign(0x40, 0x1000);

	if (OSCreateThread(thread, CCThread, 1, NULL, (u32) stack + sizeof(stack), sizeof(stack), 0, 2 | 0x10 | 8) ==
		1) {
		OSResumeThread(thread);
	} else {
		free(thread);
	}
}