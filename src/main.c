
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "types.h"

const char sdfmgr_kernel_coredump_key[0x20] = {
	0x23, 0x5A, 0x93, 0xC1, 0x02, 0x1F, 0x15, 0x53, 0xB8, 0x3D, 0x47, 0x61, 0xEC, 0xFD, 0xB4, 0xEF,
	0x63, 0x19, 0xD2, 0x47, 0xE1, 0xC5, 0x29, 0x64, 0x25, 0x73, 0xA6, 0xBA, 0xBD, 0x38, 0xCB, 0x1A
};

const char sdfmgr_kernel_coredump_iv[0x10] = {
	0x47, 0xFB, 0x05, 0x0E, 0xA6, 0xF5, 0xFE, 0xCB, 0xCC, 0x01, 0x9D, 0xE0, 0x90, 0x1F, 0xC1, 0x67
};

const char * const cause_str[0x10] = {
	"",
	"Halting Debug-mode",
	"Secure Monitor",
	"3",
	"Imprecise Data Abort",
	"T2EE Trap",
	"6",
	"7",
	"Reset",
	"Undefined",
	"SVC",
	"Prefetch Abort",
	"Precise Data Abort",
	"Software Watchpoint",
	"IRQ",
	"FIQ"
};

const char * const way_event_str[8] = {
	"Direct   branch",
	"Indirect branch",
	"Exception",
	"DMB/DSB/ISB",
	"Debug entry",
	"Debug exit",
	"6",
	"7"
};

const char * const dbg_event_string_list[] = {
	"Halt Request debug event",
	"Breakpoint debug event",
	"Asynchronous Watchpoint debug event",
	"BKPT Instruction debug event",

	"External Debug Request debug event",
	"Vector Catch debug event",
	"0x6",
	"0x7",

	"OS Unlock Catch debug event",
	"0x9",
	"Synchronous Watchpoint debug event",
	"0xB",

	"0xC",
	"0xD",
	"0xE",
	"0xF"
};

const char * const DFSR_string_list[] = {
	"0x00",
	"Alignment fault",
	"Debug event",
	"Section Access Flag fault",

	"Instruction cache maintenance fault",
	"Section Translation fault",
	"Page Access Flag fault",
	"Page Translation fault",

	"Synchronous external abort",
	"Section Domain fault",
	"0x0A",
	"Page Domain fault",

	"1st level Translation table walk synchronous external abort",
	"Section Permission fault",
	"2nd level Translation table walk synchronous external abort",
	"Page Permission fault",

	"0x10",
	"0x11",
	"0x12",
	"0x13",

	"Lockdown",
	"0x15",
	"Asynchronous external abort",
	"0x17",

	"0x18",
	"Memory access synchronous parity error",
	"Coprocessor abort",
	"0x1B",

	"1st level Translation table walk synchronous parity error",
	"0x1D",
	"2nd level Translation table walk synchronous parity error",
	"0x1F"
};

int AesCbcDecrypt(const void *src, void *dst, size_t length, const void *key, int key_size, void *iv){

	EVP_CIPHER_CTX *de;
	int p_len = length;

	de = EVP_CIPHER_CTX_new();

	EVP_CIPHER_CTX_init(de);

	if(key_size == 128){
		EVP_DecryptInit_ex(de, EVP_aes_128_cbc(), NULL, key, iv);
	}else if(key_size == 192){
		EVP_DecryptInit_ex(de, EVP_aes_192_cbc(), NULL, key, iv);
	}else if(key_size == 256){
		EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, key, iv);
	}

	EVP_DecryptUpdate(de, dst, &p_len, src, length);

	EVP_CIPHER_CTX_cleanup(de);

	return 0;
}

int print_waypoint(SceExcpmgrExceptionContext *excp_ctx, SceExcpModuleInfo *pExcpModuleInfo){

	printf("=== Print Waypoint ===\n");

	SceUInt32 waypoint_count = (excp_ctx->unkD4 >> 8) & 0x1F;

	for(int i=waypoint_count + 1;i<(waypoint_count + 0x22);i++){

		SceUInt32 wpc = i & 0x1F;

		SceArmWaypoint *waypoint = &(excp_ctx->waypoint[wpc]);

		SceUInt32 event = waypoint->event;
		if((event & 0x80000000) != 0){
			if((event & 7) == 2){

				printf("(%2d) PC:0x%08X, TARGETPC:0x%08X <<< %s Exception >>>\n", wpc, waypoint->prev_inst, waypoint->curr_inst, cause_str[(event & 0xF0) >> 4]);
				if((event & 0xF0) != 0x50){
					break;
				}

			}else if((event & 7) < 2){

				const char *mode;
				int jumptype, jumpdoes;

				uint32_t event_masked = event & 0x1800;
				if(event_masked == 0){
					mode = "ARM";
				}else if(event_masked == 0x800){
					mode = "Jzl";
				}else if(event_masked == 0x1000){
					mode = ((event & 0x200) == 0) ? "T16" : "T32";
				}else{
					mode = ((event & 0x200) == 0) ? "E16" : "E32";
				}

				jumptype = ((event & 0x100) == 0) ? 'B' : 'L';
				jumpdoes = ((event & 0x400) == 0) ? 'n' : 't';

				if(pExcpModuleInfo[wpc * 2 + 1].fingerprint == 0xFFFFFFFF){
					printf("(%2d) PC:0x%08X, TARGETPC:0x%08X %s%c%c [no module info]\n", wpc, waypoint->prev_inst, waypoint->curr_inst, mode, jumptype, jumpdoes);
				}else{

					char name[0x1C];
					snprintf(name, sizeof(name), "0x%08X", pExcpModuleInfo[wpc * 2 + 1].fingerprint);

					printf(
						"(%2d) PC:0x%08X, TARGETPC:0x%08X %s%c%c [%s + 0x%08X]\n",
						wpc, waypoint->prev_inst, waypoint->curr_inst, mode, jumptype, jumpdoes, name, waypoint->curr_inst - pExcpModuleInfo[wpc * 2 + 1].module_base
					);
				}
			}else{
				printf("(%2d) PC:0x%08X, TARGETPC:0x%08X <<< %s >>>\n", wpc, waypoint->prev_inst, waypoint->curr_inst, way_event_str[event & 7]);
			}
		}
	}

	printf("\n");

	return 0;
}

int print_psp2kerndmp(SceKernDmpHeader *pKernDmpHeader, SceKernDmpInfo *pKernDmpInfo, void *psp2kerndmp_data){

	SceKernDmpBlobHeader *pHeader = (SceKernDmpBlobHeader *)(psp2kerndmp_data);

	if(pHeader->size != sizeof(SceKernDmpBlobHeader)){
		printf("%s: pHeader->size (0x%X) != sizeof(SceKernDmpBlobHeader)\n", __FUNCTION__, pHeader->size);
		return -1;
	}

	printf("\n");
	printf("System software version: %X.%03X.%03X\n", pKernDmpInfo->fw_version >> 24, (pKernDmpInfo->fw_version >> 12) & 0xFFF, pKernDmpInfo->fw_version & 0xFFF);

	printf("\n");
	printf("ProcessId:   0x%X\n", pHeader->processId);
	printf("ThreadId:    0x%X\n", pHeader->threadId);
	printf("CpuId:       %d\n", pHeader->cpuId);
	printf("System time: %ld [usec]\n", pHeader->time);
	printf("fileHash:    0x%08X\n", pHeader->fileHash);
	printf("lineHash:    0x%08X\n", pHeader->lineHash);
	printf("funcHash:    0x%08X\n", pHeader->funcHash);
	printf("\n");

	SceKernelBacktraceInternal *pBacktrace = (SceKernelBacktraceInternal *)(&(pHeader[1]));

	if(pHeader->backtrace_number_0 != 0){
		printf("Kernel Backtrace\n");

		for(int i=0;i<pHeader->backtrace_number_0;i++){
			printf("\tpc:0x%08X sp: 0x%08X: base 0x%08X fp 0x%08X\n", pBacktrace[i].pc, pBacktrace[i].sp, pBacktrace[i].module_base, pBacktrace[i].fingerprint);
		}
	}

	pBacktrace = (SceKernelBacktraceInternal *)(&(pBacktrace[pHeader->backtrace_number_0]));

	if(pHeader->backtrace_number_1 != 0){
		printf("User Backtrace\n");

		for(int i=0;i<pHeader->backtrace_number_1;i++){
			printf("\tpc:0x%08X sp: 0x%08X: base 0x%08X fp 0x%08X\n", pBacktrace[i].pc, pBacktrace[i].sp, pBacktrace[i].fingerprint, pBacktrace[i].module_base);
		}
	}

	printf("\n");

	SceExcpmgrExceptionContext *excp_ctx = (SceExcpmgrExceptionContext *)(&(pBacktrace[pHeader->backtrace_number_1]));

	char excp_type[0x10], fault_type[0x40];

	switch(excp_ctx->unusedDC[8]){
	case 1:
		snprintf(excp_type, sizeof(excp_type), "DABT");
		break;
	case 4:
		snprintf(excp_type, sizeof(excp_type), "PABT");
		break;
	case 6:
		snprintf(excp_type, sizeof(excp_type), "UNDEF");
		break;
	default:
		snprintf(excp_type, sizeof(excp_type), "type%d", excp_ctx->unusedDC[8]);
		break;
	}

	switch(pKernDmpHeader->type){
	case 1:
		snprintf(fault_type, sizeof(fault_type), "Kernel Panic");
		break;
	case 3:
		snprintf(fault_type, sizeof(fault_type), "Kernel %s Exception", excp_type);
		break;
	default:
		snprintf(fault_type, sizeof(fault_type), "%d", pKernDmpHeader->type);
		break;
	}

	printf("Fault type: %s\n", fault_type);

	if(excp_ctx->unusedDC[5] == 0xFFFFFFFF){
		printf("\tno module info\n");
	}else{
		printf("\tFingerprint 0x%08X module base 0x%08X\n", excp_ctx->unusedDC[5], excp_ctx->unusedDC[6]);
	}

	printf("\n");

	SceExcpModuleInfo *pExcpModuleInfo = (SceExcpModuleInfo *)(&(excp_ctx[1]));

	print_waypoint(excp_ctx, pExcpModuleInfo);

	printf("Fault register\n");
	printf("r0-r3 : 0x%08X 0x%08X 0x%08X 0x%08X\n", excp_ctx->r0, excp_ctx->r1, excp_ctx->r2, excp_ctx->r3);
	printf("r4-r7 : 0x%08X 0x%08X 0x%08X 0x%08X\n", excp_ctx->r4, excp_ctx->r5, excp_ctx->r6, excp_ctx->r7);
	printf("r8-r11: 0x%08X 0x%08X 0x%08X 0x%08X\n", excp_ctx->r8, excp_ctx->r9, excp_ctx->r10, excp_ctx->r11);
	printf("ip    : 0x%08X\n", excp_ctx->r12);
	printf("sp    : 0x%08X\n", excp_ctx->sp);
	printf("lr    : 0x%08X\n", excp_ctx->lr);
	printf("pc    : 0x%08X\n", excp_ctx->address_of_faulting_instruction);
	printf("SPSR  : 0x%08X\n", excp_ctx->SPSR);

	for(int i=0;i<0x20;i+=4){
		printf(
			"d%-2d-d%-2d : 0x%016lX 0x%016lX 0x%016lX 0x%016lX\n",
			i + 0, i + 3,
			excp_ctx->VFP_registers[i + 0x0],
			excp_ctx->VFP_registers[i + 0x1],
			excp_ctx->VFP_registers[i + 0x2],
			excp_ctx->VFP_registers[i + 0x3]
		);
	}

	printf("FPEXC : 0x%08X\n", excp_ctx->FPEXC);
	printf("FPSCR : 0x%08X\n", excp_ctx->FPSCR);
	printf("\n");
	printf("Context ID : 0x%08X\n", excp_ctx->CONTEXTIDR);
	printf("DACR       : 0x%08X\n", excp_ctx->DACR);
	printf("TTBR1      : 0x%08X\n", excp_ctx->TTBR1);
	printf("TPIDRURW   : 0x%08X\n", excp_ctx->TPIDRURW);
	printf("TPIDRURO   : 0x%08X\n", excp_ctx->TPIDRURO);
	printf("TPIDRPRW   : 0x%08X\n", excp_ctx->TPIDRPRW);

	uint32_t DFSR = excp_ctx->DFSR;
	printf("DFSR           0x%08X [ %s ]\n", DFSR, DFSR_string_list[(DFSR & 0xF) | ((DFSR & 0x400) >> 0x6)]);
	printf("DFAR           0x%08X [ %s ]\n", excp_ctx->DFAR, ((DFSR & 0x800) == 0) ? "Read" : "Write");

	if(excp_ctx->IFSR != 0){ // Provisional, need more RE

		uint32_t IFSR = excp_ctx->IFSR;
		printf("IFSR           : 0x%08X [ %s ]\n", IFSR, DFSR_string_list[(IFSR & 0xF) | ((IFSR & 0x400) >> 0x6)]);

		if((IFSR & 0x40F) == 2){
			printf(
				"DBGDSCR        : 0x%08X [ %s ]\n",
				excp_ctx->DBGSCRext,
				dbg_event_string_list[(excp_ctx->DBGSCRext >> 2) & 0xF]
			);
		}
	}

	printf("\n");

	if(pHeader->unk_0x34 == 0x22){
		SceKernelThreadRegisterInfo *pThreadRegisterInfo = (SceKernelThreadRegisterInfo *)(&(pExcpModuleInfo[0x40]));

		SceExcpModuleInfo2 *pExcpModuleInfo2 = (SceExcpModuleInfo2 *)(&(pThreadRegisterInfo[1]));

		printf("Fault saved thread register\n");
		printf("r0-r3 : 0x%08X 0x%08X 0x%08X 0x%08X\n", pThreadRegisterInfo->reg[0x0], pThreadRegisterInfo->reg[0x1], pThreadRegisterInfo->reg[0x2], pThreadRegisterInfo->reg[0x3]);
		printf("r4-r7 : 0x%08X 0x%08X 0x%08X 0x%08X\n", pThreadRegisterInfo->reg[0x4], pThreadRegisterInfo->reg[0x5], pThreadRegisterInfo->reg[0x6], pThreadRegisterInfo->reg[0x7]);
		printf("r8-r11: 0x%08X 0x%08X 0x%08X 0x%08X\n", pThreadRegisterInfo->reg[0x8], pThreadRegisterInfo->reg[0x9], pThreadRegisterInfo->reg[0xA], pThreadRegisterInfo->reg[0xB]);
		printf("ip-pc : 0x%08X 0x%08X 0x%08X 0x%08X\n", pThreadRegisterInfo->reg[0xC], pThreadRegisterInfo->unk_0x38, pThreadRegisterInfo->sp, pThreadRegisterInfo->pc);
		printf("cpsr : 0x%08X fcpsr : 0x%08X\n", pThreadRegisterInfo->cpsr, pThreadRegisterInfo->fpscr);
	}

	return 0;
}

int main(int argc, char **argp){

	FILE *fd;
	SceKernDmpHeader kerndmp_header;
	void *content_blob;

	fd = fopen(argp[1], "rb");
	if(fd == NULL){
		printf("Failed open to .psp2kerndmp\n");
		return EXIT_FAILURE;
	}

	content_blob = NULL;

	if(fread(&kerndmp_header, sizeof(kerndmp_header), 1, fd) == 1){
		content_blob = malloc(kerndmp_header.content_size);
		if(content_blob != NULL && fread(content_blob, kerndmp_header.content_size, 1, fd) != 1){
			free(content_blob);
			content_blob = NULL;
		}
	}

	fclose(fd);
	fd = NULL;

	if(content_blob != NULL){

		SceKernDmpInfo *pInfo = (SceKernDmpInfo *)(content_blob);

		if((pInfo->flags & 0x20000000) != 0){

			char iv[0x10];

			memcpy(iv, sdfmgr_kernel_coredump_iv, sizeof(iv));

			AesCbcDecrypt(content_blob + pInfo->offset, content_blob + pInfo->offset, pInfo->enc_blob_size, sdfmgr_kernel_coredump_key, 256, iv);
		}else if((pInfo->flags & 0x10000000) == 0){
			printf("?\n");
		}

		print_psp2kerndmp(&kerndmp_header, pInfo, content_blob + pInfo->offset);

		free(content_blob);
		content_blob = NULL;
	}

	return 0;
}
