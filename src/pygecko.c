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
#include "diskdumper.h"
#include "utils/utils.h"

struct pygecko_bss_t {
	int error, line;
	void *thread;
	unsigned char stack[0x6F00];
};

int validateAddressRange(int starting_address, int ending_address);

#define CHECK_ERROR(cond) if (cond) { bss->line = __LINE__; goto error; }
#define errno (*__gh_errno_ptr())
#define MSG_DONTWAIT 32
#define EWOULDBLOCK 6
#define FS_BUFFER_SIZE 0x1000
#define DATA_BUFFER_SIZE 0x5000

#define CHECK_FUNCTION_FAILED(returnValue, functionName) \
    if (returnValue < 0) { \
        char buffer[50] = {0}; \
        __os_snprintf(buffer, 50, "%s failed with return value: %i", functionName, returnValue); \
        OSFatal(buffer); \
    }

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

// TODO Is this allocation needed?
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

/*static void DumpFile(void *client, void *commandBlock, SendData *sendData, char *path, unsigned int fileSize) {
	sendData->tag = 0x02;
	memcpy(&sendData->data[0], &fileSize, 4);
	sendData->length = snprintf((char *) sendData->data + 4, FS_BUFFER_SIZE - 4, "%s", path) + 4 + 1;
	// sendwait(iClientSocket, sendData, sizeof(SendData) + sendData->length);

	int ret = 0; // recvwait(iClientSocket, (char*)sendData, sizeof(SendData) + 1);
	if (ret < (int) (sizeof(SendData) + 1) || (sendData->data[0] != 1)) {
		return;
	}

	unsigned char *dataBuffer = (unsigned char *) memalign(0x40, FS_BUFFER_SIZE);
	if (!dataBuffer) {
		return;
	}

	int fileDescriptor = 0;
	if (FSOpenFile(client, commandBlock, path, "r", &fileDescriptor, -1) != FS_STATUS_OK) {
		free(dataBuffer);
		sendData->tag = 0x04;
		sendData->length = 0;
		// sendwait(iClientSocket, sendData, sizeof(SendData) + sendData->length);
		return;
	}

	// Copy rpl in memory
	while ((ret = FSReadFile(client, commandBlock, dataBuffer, 0x1, FS_BUFFER_SIZE, fileDescriptor, 0, -1)) > 0) {
		sendData->tag = 0x03;
		sendData->length = ret;
		memcpy(sendData->data, dataBuffer, sendData->length);

		// if(sendwait(iClientSocket, sendData, sizeof(SendData) + sendData->length) < 0) {
		//	break;
		// }
	}

	sendData->tag = 0x04;
	sendData->length = 0;
	// sendwait(iClientSocket, sendData, sizeof(SendData) + sendData->length);

	FSCloseFile(client, commandBlock, fileDescriptor, -1);
	free(dataBuffer);
}*/

static int sendDirectoryData(void *client, void *commandBlock, SendData *sendData, char *path) {
	int dataHandle = 0;

	sendData->tag = 0x01;
	sendData->length = snprintf((char *) sendData->data, FS_BUFFER_SIZE, "%s", path) + 1;
	// sendwait(iClientSocket, sendData, sizeof(SendData) + sendData->length);

	if (FSOpenDir(client, commandBlock, path, &dataHandle, -1) != 0) {
		return -1;
	}

	FSDirEntry *dirEntry = (FSDirEntry *) malloc(sizeof(FSDirEntry));

	while (FSReadDir(client, commandBlock, dataHandle, dirEntry, -1) == 0) {
		int pathLength = strlen(path);
		snprintf(path + pathLength, FS_MAX_FULLPATH_SIZE - pathLength, "/%s", dirEntry->name);

		if (dirEntry->stat.flag & 0x80000000) {
			sendDirectoryData(client, commandBlock, sendData, path);
		} else {
			// DumpFile(client, commandBlock, sendData, path, dirEntry->stat.size);
		}
		path[pathLength] = 0;
	}
	free(dirEntry);
	FSCloseDir(client, commandBlock, dataHandle, -1);
	return 0;
}

static int rungecko(struct pygecko_bss_t *bss, int clientfd) {
	int ret;

	// Hold the command and the data
	unsigned char buffer[1 + DATA_BUFFER_SIZE];

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

					/*ret = checkbyte(clientfd);
					if (ret == 0xcc)
						goto next_cmd;*/

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
				// TODO Too slow on big ranges...

				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				// Retrieve the data
				int starting_address = ((int *) buffer)[0];
				int ending_address = ((int *) buffer)[1];

				int is_address_range_valid = validateAddressRange(starting_address, ending_address);

				sendbyte(bss, clientfd, (unsigned char) is_address_range_valid);
				break;
			}
			case 0x0b: { /* cmd_writekern */
				void *ptr, *value;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

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

				// Receive the file path length
				ret = recvwait(bss, clientfd, buffer, 4);
				CHECK_FUNCTION_FAILED(ret, "recvwait (file path length)");
				int file_path_length = ((int *) buffer)[0];
				// ASSERT_INTEGER(file_path_length, 41, "File path")

				if (file_path_length >= 0 &&
					file_path_length <= FS_MAX_FULLPATH_SIZE) {
					// Receive the file path string
					ret = recvwait(bss, clientfd, buffer, file_path_length);
					CHECK_FUNCTION_FAILED(ret, "recvwait (file path)");
					strcpy(file_path, (char *) buffer);
					// ASSERT_STRING(file_path, "/vol/content/afghanistan_gump_arena.ipak");

					// Initialize the file system
					ret = FSInit();
					CHECK_FUNCTION_FAILED(ret, "FSInit")

					// Allocate the client
					void *client = malloc(FS_CLIENT_SIZE);
					CHECK_ALLOCATED(client, "Client")

					// Register the client
					ret = FSAddClientEx(client, 0, -1);
					CHECK_FUNCTION_FAILED(ret, "FSAddClientEx")

					// Allocate the command block
					void *commandBlock = malloc(FS_CMD_BLOCK_SIZE);
					CHECK_ALLOCATED(client, "Command block")

					FSInitCmdBlock(commandBlock);

					// Open the file
					int handle;
					int status = FSOpenFile(client, commandBlock, file_path, "r", &handle, -1);

					if (status == FS_STATUS_OK) {
						// Send the OK status
						((int *) buffer)[0] = status;
						ret = sendwait(bss, clientfd, buffer, 4);
						CHECK_FUNCTION_FAILED(ret, "sendwait (OK status)")

						// Retrieve the file statistics
						FSStat stat;
						ret = FSGetStatFile(client, commandBlock, handle, &stat, -1);
						CHECK_FUNCTION_FAILED(ret, "FSGetStatFile")

						// Send the total bytes count
						int totalBytes = (int) stat.size;
						((int *) buffer)[0] = totalBytes;
						ret = sendwait(bss, clientfd, buffer, 4);
						CHECK_FUNCTION_FAILED(ret, "sendwait (total bytes)")

						// Allocate the file bytes buffer
						unsigned int file_buffer_size = 0x2000;
						char *fileBuffer = (char *) OSAllocFromSystem(file_buffer_size, 0x40);
						CHECK_ALLOCATED(fileBuffer, "File buffer")

						int totalBytesRead = 0;
						while (totalBytesRead < totalBytes) {
							int bytesRead = FSReadFile(client, commandBlock, fileBuffer, 1, file_buffer_size, handle, 0,
													   -1);
							CHECK_FUNCTION_FAILED(bytesRead, "FSReadFile")

							// Send file bytes
							ret = sendwait(bss, clientfd, fileBuffer, bytesRead);
							CHECK_FUNCTION_FAILED(ret, "sendwait (file buffer)")

							totalBytesRead += bytesRead;
						}

						ret = FSCloseFile(client, commandBlock, handle, -1);
						CHECK_FUNCTION_FAILED(ret, "FSCloseFile")

						OSFreeToSystem(fileBuffer);
					} else {
						// Send the error status
						((int *) buffer)[0] = status;
						ret = sendwait(bss, clientfd, buffer, 4);
						CHECK_FUNCTION_FAILED(ret, "sendwait (error status)")
					}

					free(commandBlock);
					FSDelClient(client);
					free(client);
					FSShutdown();
				} else {
					OSFatal("File path length exceeded");
				}

				break;
			}
			case 0x53: { /* cmd_read_directory */
				// TODO Crashes (somewhere in this function)
				FSInit();

				void *commandBlock = malloc(FS_CMD_BLOCK_SIZE);
				FSInitCmdBlock(commandBlock);

				void *client = malloc(FS_CLIENT_SIZE);
				FSAddClientEx(client, 0, -1);

				char *path = (char *) malloc(FS_MAX_FULLPATH_SIZE);
				strcpy(path, "/vol/content");

				SendData *sendData = (SendData *) memalign(0x20, ALIGN32(sizeof(SendData) + FS_BUFFER_SIZE));

				sendDirectoryData(client, commandBlock, sendData, path);

				FSDelClient(client);
				FSShutdown();
				free(commandBlock);
				free(client);
				free(path);

				break;
			}
			case 0x54: { /* cmd_replace_file */
				// TODO
			}
			case 0x55: { /* cmd_code_handler_install_address */
				((int *) buffer)[0] = CODE_HANDLER_INSTALL_ADDRESS;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);

				break;
			}
			case 0x60: { /* cmd_follow_pointer */
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				int baseAddress = ((int *) buffer)[0];
				int offsetsCount = ((int *) buffer)[1];

				ret = recvwait(bss, clientfd, buffer, offsetsCount * 4);
				CHECK_ERROR(ret < 0);
				int *offsets = (int *) buffer;

				int destinationAddress = baseAddress;

				for (int offsetIndex = 0; offsetIndex < offsetsCount; offsetIndex++) {
					int pointerValue = *(int *) destinationAddress;
					int offset = offsets[offsetIndex];
					destinationAddress = pointerValue + offset;

					bool isValidDestinationAddress = OSIsAddressValid((const void *) destinationAddress)
													 && destinationAddress >= 0x10000000
													 && destinationAddress < 0x50000000;

					if (!isValidDestinationAddress) {
						destinationAddress = -1;

						break;
					}
				}

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

/*Validates the address range (last address inclusive) but is SLOW on bigger ranges */
int validateAddressRange(int starting_address, int ending_address) {
	// __OSValidateAddressSpaceRange(1, (void *) starting_address, ending_address - starting_address);
	for (int current_address = starting_address; current_address <= ending_address; current_address++) {
		int is_current_address_valid = OSIsAddressValid((void *) current_address);

		if (!is_current_address_valid) {
			return 0;
		}
	}

	return 1;
}

static int start(int argc, void *argv) {
	int sockfd = -1, clientfd = -1, ret = 0, len;
	struct sockaddr_in addr;
	struct pygecko_bss_t *bss = argv;

	socket_lib_init();

	while (1) {
		addr.sin_family = AF_INET;
		addr.sin_port = 7331;
		addr.sin_addr.s_addr = 0;
		sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		CHECK_ERROR(sockfd == -1);
		ret = bind(sockfd, (void *) &addr, 16);
		CHECK_ERROR(ret < 0);
		ret = listen(sockfd, 20);
		CHECK_ERROR(ret < 0);

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

/*void start_pygecko(void) {
	struct pygecko_bss_t *bss;

	unsigned int stack = (unsigned int) memalign(0x40, 0x100);
	stack += 0x100;

	bss = memalign(0x40, sizeof(struct pygecko_bss_t));
	if (bss == 0)
		return;
	memset(bss, 0, sizeof(struct pygecko_bss_t));

	if (OSCreateThread(&bss->thread, start, 1, bss, (u32) bss->stack + sizeof(bss->stack), sizeof(bss->stack), 0,
					   0xc) == 1) {
		OSResumeThread(&bss->thread);
	} else {
		free(bss);
	}
}*/

void start_pygecko(void) {
	unsigned int stack = (unsigned int) memalign(0x40, 0x100);
	stack += 0x100;

	// Create the thread
	void *thread = memalign(0x40, 0x1000);

	if (OSCreateThread(thread, CCThread, 1, NULL, (u32) stack + sizeof(stack), sizeof(stack), 0, 2 | 0x10 | 8) == 1) {
		OSResumeThread(thread);
	} else {
		free(thread);
	}
}