#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include "common/common.h"
#include "main.h"
#include "dynamic_libs/socket_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "kernel/syscalls.h"

struct pygecko_bss_t {
	int error, line;
	void *thread;
	unsigned char stack[0x8000];
};

#define CHECK_ERROR(cond) if (cond) { bss->line = __LINE__; goto error; }
#define errno (*__gh_errno_ptr())
#define MSG_DONTWAIT 32
#define EWOULDBLOCK 6
#define DATA_BUFFER_SIZE 0x5000

unsigned char *memcpy_buffer[DATA_BUFFER_SIZE];

void pygecko_memcpy(unsigned char *dst, unsigned char *src, unsigned int len) {
	memcpy(memcpy_buffer, src, len);
	SC0x25_KernelCopyData((unsigned int) OSEffectiveToPhysical(dst), (unsigned int) &memcpy_buffer, len);
	DCFlushRange(dst, len);
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
				const unsigned char *ptr, *end;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);
				ptr = ((const unsigned char **) buffer)[0];
				end = ((const unsigned char **) buffer)[1];

				while (ptr != end) {
					int len, i;

					len = (int) (end - ptr);
					if (len > DATA_BUFFER_SIZE)
						len = DATA_BUFFER_SIZE;
					for (i = 0; i < len; i++)
						if (ptr[i] != 0) break;

					if (i == len) { // all zero!
						ret = sendbyte(bss, clientfd, 0xb0);
						CHECK_ERROR(ret < 0);
					} else {
						memcpy(buffer + 1, ptr, len);
						buffer[0] = 0xbd;
						ret = sendwait(bss, clientfd, buffer, len + 1);
						CHECK_ERROR(ret < 0);
					}

					ret = checkbyte(clientfd);
					if (ret == 0xcc) /* GCFAIL */
						goto next_cmd;
					ptr += len;
				}
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
				unsigned char *current_address, *end_address;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);
				current_address = ((unsigned char **) buffer)[0];
				end_address = ((unsigned char **) buffer)[1];

				while (current_address != end_address) {
					int length;

					length = (int) (end_address - current_address);
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					ret = recvwait(bss, clientfd, buffer, length);
					CHECK_ERROR(ret < 0);
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

		next_cmd:
		continue;
	}

	error:
	bss->error = ret;
	return 0;
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
		sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  //open a file handle to socket
		CHECK_ERROR(sockfd == -1);
		ret = bind(sockfd, (void *) &addr, 16);
		CHECK_ERROR(ret < 0);
		ret = listen(sockfd, 20);
		CHECK_ERROR(ret < 0);

		while (1) {
			len = 16;
			clientfd = accept(sockfd, (void *) &addr, &len);
			CHECK_ERROR(clientfd == -1);
			ret = rungecko(bss, clientfd);
			CHECK_ERROR(ret < 0);
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
		void (*entrypoint)() = (void *) INSTALL_ADDR;

		while (1) {
			usleep(9000);
			entrypoint();
		}
	}
	return 0;
}

void start_pygecko(void) {
	unsigned int stack = (unsigned int) memalign(0x40, 0x1000);
	stack += 0x1000;

	/* Create the thread */
	void *thread = memalign(0x40, 0x1000);

	if (OSCreateThread(thread, CCThread, 1, NULL, (u32) stack + sizeof(stack), sizeof(stack), 0, 2 | 0x10 | 8) == 1) {
		OSResumeThread(thread);
	} else {
		free(thread);
	}
}