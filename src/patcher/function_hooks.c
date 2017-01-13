#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "../common/common.h"
#include "../dynamic_libs/os_functions.h"
#include "../kernel/kernel_functions.h"
#include "function_hooks.h"
#include "../dynamic_libs/gx2_types.h"

#define LIB_CODE_RW_BASE_OFFSET                         0xC1000000
#define CODE_RW_BASE_OFFSET                             0x00000000

#define DECL(res, name, ...) \
        res (* real_ ## name)(__VA_ARGS__); \
        res my_ ## name(__VA_ARGS__)

/* *****************************************************************************
 * Creates function pointer array
 * ****************************************************************************/
// #define MAKE_MAGIC(x, lib) { (unsigned int) my_ ## x, (unsigned int) &real_ ## x, lib, # x }

#define MAKE_MAGIC(x, lib, functionType) { (unsigned int) my_ ## x, (unsigned int) &real_ ## x, lib, # x,0,0,functionType,0}

DECL(void, GX2CopyColorBufferToScanBuffer, const GX2ColorBuffer *colorBuffer,
	 s32 scan_target) {
	// TODO Does not execute
	GX2Surface surface = colorBuffer->surface;
	u32 image_size = surface.image_size;
	char buffer[100] = {0};
	__os_snprintf(buffer, 100, "Image size: %i", image_size);
	OSFatal(buffer);

	real_GX2CopyColorBufferToScanBuffer(colorBuffer, scan_target);
}

DECL(int, FSInit, void) {
	return real_FSInit();
}

DECL(int, socket_lib_finish, void) {
	return 0;
}

static const struct hooks_magic_t {
	const unsigned int replaceAddr;
	const unsigned int replaceCall;
	const unsigned int library;
	const char functionName[50];
	unsigned int realAddr;
	unsigned int restoreInstruction;
	unsigned char functionType;
	unsigned char alreadyPatched;
} method_hooks[] = {
		MAKE_MAGIC(FSInit, LIB_CORE_INIT, STATIC_FUNCTION),
		MAKE_MAGIC(socket_lib_finish, LIB_CORE_INIT, STATIC_FUNCTION),
		MAKE_MAGIC(GX2CopyColorBufferToScanBuffer, LIB_GX2, DYNAMIC_FUNCTION),
};

//! buffer to store our 2 instructions needed for our replacements
//! the code will be placed in the address of that buffer - CODE_RW_BASE_OFFSET
//! avoid this buffer to be placed in BSS and reset on start up
volatile unsigned int fs_method_calls[sizeof(method_hooks) / sizeof(struct hooks_magic_t) * 2];

void PatchMethodHooks(void) {
	restore_instructions_t *restore = RESTORE_INSTR_ADDR;
	//! check if it is already patched
	if (restore->magic == RESTORE_INSTR_MAGIC)
		return;

	restore->magic = RESTORE_INSTR_MAGIC;
	restore->instr_count = 0;

	bat_table_t table;
	KernelSetDBATs(&table);

	/* Patch branches to it. */
	volatile unsigned int *space = &fs_method_calls[0];

	int method_hooks_count = sizeof(method_hooks) / sizeof(struct hooks_magic_t);

	for (int i = 0; i < method_hooks_count; i++) {
		unsigned int repl_addr = method_hooks[i].replaceAddr;
		unsigned int call_addr = method_hooks[i].replaceCall;

		unsigned int real_addr = 0;

		if (strcmp(method_hooks[i].functionName, "OSDynLoad_Acquire") == 0) {
			memcpy(&real_addr, &OSDynLoad_Acquire, 4);
		} else {
			OSDynLoad_FindExport(coreinit_handle, 0, method_hooks[i].functionName, &real_addr);
		}

		// fill the restore instruction section
		restore->data[restore->instr_count].addr = real_addr;
		restore->data[restore->instr_count].instr = *(volatile unsigned int *) (LIB_CODE_RW_BASE_OFFSET + real_addr);
		restore->instr_count++;

		// set pointer to the real function
		*(volatile unsigned int *) (call_addr) = (unsigned int) (space) - CODE_RW_BASE_OFFSET;
		DCFlushRange((void *) (call_addr), 4);

		// fill the instruction of the real function
		*space = *(volatile unsigned int *) (LIB_CODE_RW_BASE_OFFSET + real_addr);
		space++;

		// jump to real function skipping the first/replaced instruction
		*space = 0x48000002 | ((real_addr + 4) & 0x03fffffc);
		space++;
		DCFlushRange((void *) (space - 2), 8);
		ICInvalidateRange((unsigned char *) (space - 2) - CODE_RW_BASE_OFFSET, 8);

		unsigned int replace_instr = 0x48000002 | (repl_addr & 0x03fffffc);
		*(volatile unsigned int *) (LIB_CODE_RW_BASE_OFFSET + real_addr) = replace_instr;
		DCFlushRange((void *) (LIB_CODE_RW_BASE_OFFSET + real_addr), 4);
		ICInvalidateRange((void *) (real_addr), 4);
	}

	KernelRestoreDBATs(&table);
}

/* ****************************************************************** */
/*                  RESTORE ORIGINAL INSTRUCTIONS                     */
/* ****************************************************************** */
void RestoreInstructions(void) {
	bat_table_t table;
	KernelSetDBATs(&table);

	restore_instructions_t *restore = RESTORE_INSTR_ADDR;
	if (restore->magic == RESTORE_INSTR_MAGIC) {
		for (unsigned int i = 0; i < restore->instr_count; i++) {
			*(volatile unsigned int *) (LIB_CODE_RW_BASE_OFFSET + restore->data[i].addr) = restore->data[i].instr;
			DCFlushRange((void *) (LIB_CODE_RW_BASE_OFFSET + restore->data[i].addr), (u32) 4);
			ICInvalidateRange((void *) restore->data[i].addr, (u32) 4);
		}
	}
	restore->magic = 0;
	restore->instr_count = 0;

	KernelRestoreDBATs(&table);
	KernelRestoreInstructions();
}