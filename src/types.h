
#ifndef _TYPES_H_
#define _TYPES_H_


#include <stdint.h>


typedef uint8_t SceUInt8;
typedef uint16_t SceUInt16;
typedef uint32_t SceUInt32;
typedef uint64_t SceUInt64;
typedef signed int SceUID;
typedef unsigned int SceSize;
typedef SceSize SceUIntPtr;

typedef struct SceKernDmpHeader { // size is 0xC-bytes
	SceUInt32 unk_0x00;
	SceUInt32 type;
	SceSize content_size;
} SceKernDmpHeader;

typedef struct SceKernDmpInfo { // size is 0x28-bytes
	SceUInt32 fw_version;
	SceUInt32 unk_0x10;
	SceUInt32 flags;
	SceSize enc_blob_size;
	SceUInt32 offset;
	SceUInt32 unk_0x20;
	SceUInt8 session_id[0x10];
} SceKernDmpInfo;

typedef struct SceKernDmpBlobHeader { // size is 0x38-bytes
	int size;
	SceUID processId;
	SceUID threadId;
	SceUInt32 cpuId;
	SceUInt64 time;
	SceUInt32 fileHash;
	SceUInt32 lineHash;
	SceUInt32 funcHash;
	SceSize backtrace_number_0;
	SceSize backtrace_number_1;
	SceSize backtrace_elem_size;
	SceSize some_size;
	SceSize unk_0x34;
} SceKernDmpBlobHeader;

typedef struct SceKernelBacktraceInternal { // size is 0x10-bytes
	SceUIntPtr sp;
	SceUIntPtr pc;
	SceUInt32 fingerprint;
	SceUIntPtr module_base;
} SceKernelBacktraceInternal;

typedef enum SceExcpKind {
	SCE_EXCP_RESET                = 0,
	SCE_EXCP_UNDEF_INSTRUCTION    = 1,
	SCE_EXCP_SVC                  = 2,
	SCE_EXCP_PABT                 = 3,
	SCE_EXCP_DABT                 = 4,
	SCE_EXCP_UNUSED               = 5,
	SCE_EXCP_IRQ                  = 6,
	SCE_EXCP_FIQ                  = 7
} SceExcpKind;

typedef struct SceArmWaypoint { //!< Size is 0x10-bytes
	SceUInt32 flags;
	SceUIntPtr prev_inst; // pc
	SceUIntPtr curr_inst; // target
	SceUInt32 event;
} SceArmWaypoint;

typedef struct SceExcpmgrExceptionContext { //!< Size is 0x400 on FW 3.60
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;
	uint32_t sp;
	uint32_t lr;
	uint32_t address_of_faulting_instruction;	//<! Address where the faulty instruction is located
	SceExcpKind ExceptionKind; 			//<! The kind of exception the CPU encountered
	uint32_t SPSR;
	uint32_t CPACR;
	uint32_t FPSCR;
	uint32_t FPEXC;
	uint32_t CONTEXTIDR;
	uint32_t TPIDRURW;
	uint32_t TPIDRURO;
	uint32_t TPIDRPRW;
	uint32_t TTBR1;
	uint32_t unused68;
	uint32_t DACR;
	uint32_t DFSR;
	uint32_t IFSR;
	uint32_t DFAR;
	uint32_t IFAR;
	uint32_t PAR;
	uint32_t TEEHBR;
	uint32_t PMCR;
	uint32_t PMCNTENSET;
	uint32_t PMCNTENSET_2; //<! Second copy of PMCNTENSET
	uint32_t PMSELR;
	uint32_t PMCCNTR;
	uint32_t PMUSERENR;
	uint32_t PMXEVTYPER0;
	uint32_t PMXEVCNTR0;
	uint32_t PMXEVTYPER1;
	uint32_t PMXEVCNTR1;
	uint32_t PMXEVTYPER2;
	uint32_t PMXEVCNTR2;
	uint32_t PMXEVTYPER3;
	uint32_t PMXEVCNTR3;
	uint32_t PMXEVTYPER4;
	uint32_t PMXEVCNTR4;
	uint32_t PMXEVTYPER5;
	uint32_t PMXEVCNTR5;
	uint32_t unusedD0;
	uint32_t unkD4; 		//<! Comes from SceVfpIntRegs memblock
	uint32_t DBGSCRext;
	uint32_t unusedDC[9];  
	uint64_t VFP_registers[32]; //<! Content of floating-point registers d0-d31
	SceArmWaypoint waypoint[0x20]; //<! Comes from SceVfpIntRegs memblock
} SceExcpmgrExceptionContext;

typedef struct SceExcpModuleInfo { //!< Size is 0x8-bytes
	SceUInt32 fingerprint;
	SceUIntPtr module_base;
} SceExcpModuleInfo;

typedef struct SceKernelThreadRegisterInfo { // size is 0x60-bytes
	SceUInt32 reg[0xD];
	SceUInt32 unk_0x34;
	SceUInt32 unk_0x38; // ex:0xB90B45, lr?
	SceUInt32 fpscr;
	SceUInt32 unk_0x40;
	SceUInt32 unk_0x44;
	SceUInt32 unk_0x48;
	SceUInt32 unk_0x4C;
	SceUInt32 sp;
	SceUInt32 lr;
	SceUInt32 pc;
	SceUInt32 cpsr;
} SceKernelThreadRegisterInfo;

typedef struct SceExcpModuleInfo2 { //!< Size is 0x24-bytes
	SceUInt32 fingerprint;
	SceUIntPtr module_base;
	char name[0x1C];
} SceExcpModuleInfo2;


#endif /* _TYPES_H_ */
