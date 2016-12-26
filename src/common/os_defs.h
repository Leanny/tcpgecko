#ifndef __OS_DEFS_H_
#define __OS_DEFS_H_

#ifdef __cplusplus
extern "C" {
#endif

/*struct OSThread;

struct OSThreadLink {
	OSThread *next;
	OSThread *prev;
};

struct OSThreadQueue {
	OSThread *head;
	OSThread *tail;
	void *parentStruct;
	u32 reserved;
};

struct OSMessage {
	u32 message;
	u32 data0;
	u32 data1;
	u32 data2;
};

struct OSMessageQueue {
	u32 tag;
	char *name;
	u32 reserved;

	OSThreadQueue sendQueue;
	OSThreadQueue recvQueue;
	OSMessage *messages;
	int msgCount;
	int firstIndex;
	int usedCount;
};

struct OSContext {
	char tag[8];

	u32 gpr[32];

	u32 cr;
	u32 lr;
	u32 ctr;
	u32 xer;

	u32 srr0;
	u32 srr1;

	u32 ex0;
	u32 ex1;

	u32 exception_type;
	u32 reserved;

	double fpscr;
	double fpr[32];

	u16 spinLockCount;
	u16 state;

	u32 gqr[8];
	u32 pir;
	double psf[32];

	u64 coretime[3];
	u64 starttime;

	u32 error;
	u32 attributes;

	u32 pmc1;
	u32 pmc2;
	u32 pmc3;
	u32 pmc4;
	u32 mmcr0;
	u32 mmcr1;
};

typedef int (*ThreadFunc)(int argc, void *argv);

struct OSThread {
	OSContext context;

	u32 txtTag;
	u8 state;
	u8 attr;

	short threadId;
	int suspend;
	int priority;

	char _[0x394 - 0x330];

	void *stackBase;
	void *stackEnd;

	ThreadFunc entryPoint;

	char _3A0[0x6A0 - 0x3A0];
};*/

typedef struct _OsSpecifics
{
    unsigned int addr_OSDynLoad_Acquire;
    unsigned int addr_OSDynLoad_FindExport;
    unsigned int addr_OSTitle_main_entry;

    unsigned int addr_KernSyscallTbl1;
    unsigned int addr_KernSyscallTbl2;
    unsigned int addr_KernSyscallTbl3;
    unsigned int addr_KernSyscallTbl4;
    unsigned int addr_KernSyscallTbl5;
} OsSpecifics;

#ifdef __cplusplus
}
#endif

#endif // __OS_DEFS_H_
