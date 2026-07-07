/*
 * (c) 2025 Raphael Mudge
 * A very quick'n'dirty shellcode injector.
 *
 * Part of the Crystal Palace distribution
 *
 * BSD 3-clause license.
 */
#include <windows.h>
#include <stdio.h>
#include <winsock.h>

DWORD GetVolSerialNo() {
	DWORD volumeSerialNumber = 0;
	GetVolumeInformationA("c:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0);
	return volumeSerialNumber;
}

/*
 * When no arguments are provided, run.x##.exe prints usage information AND several KEY=VALUE
 * pairs to aid working with some of the Tradecraft Garden samples.
 *
 * The ./link command in Crystal Palace takes KEY=VAL arguments, which are just a bunch of bytes
 * specified in hex. The ./link command has no knowledge of the types we're passing (e..g, a char
 * array, a pointer, something else)? and so we need to print the values in little-endian byte
 * order to make everything work out right.
 */
#ifdef WIN_X64
typedef union {
	ULONG_PTR value;
	struct {
		DWORD a;
		DWORD b;
	} parts;
} QWORD;

ULONG_PTR rev64(ULONG_PTR val) {
	QWORD temp = { .value = val };
	DWORD swap;

	swap = temp.parts.b;
	temp.parts.b = htonl(temp.parts.a);
	temp.parts.a = htonl(swap);

	return temp.value;
}
#endif

LONG WINAPI CrashHandler(EXCEPTION_POINTERS * pExceptionPointers) {
	PEXCEPTION_RECORD ExceptionRecord = pExceptionPointers->ExceptionRecord;

	switch (ExceptionRecord->ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_ILLEGAL_INSTRUCTION:
		case EXCEPTION_BREAKPOINT:
		case EXCEPTION_PRIV_INSTRUCTION:
		case EXCEPTION_STACK_OVERFLOW:
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			break;
		default:
			return EXCEPTION_CONTINUE_SEARCH;
	}

	/* basic crash info */
	printf("** CRASH DETECTED **\n\n");
	printf("Code:         %08lX\n", ExceptionRecord->ExceptionCode);
	printf("Address:      %p\n", ExceptionRecord->ExceptionAddress);

	/* print GetLastError() - I've had times when a missing DLL got me */
	if (GetLastError() != 0) {
		char * buffer;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, (LPTSTR)&buffer, 0, NULL);

		if (buffer) {
			printf("GetLastError: %lu - %s\n", GetLastError(), buffer);
			LocalFree(buffer);
		}
		else {
			printf("GetLastError: %lu\n\n", GetLastError());
		}
	}
	else {
		printf("\n");
	}

	/* register context */
	PCONTEXT ContextRecord = pExceptionPointers->ContextRecord;
	printf("REGISTERS:\n");
#ifdef WIN_X64
	printf("RAX %016llX ", ContextRecord->Rax);
	printf("R8  %016llX\n", ContextRecord->R8);

	printf("RBX %016llX ", ContextRecord->Rbx);
	printf("R9  %016llX\n", ContextRecord->R9);

	printf("RCX %016llX ", ContextRecord->Rcx);
	printf("R10 %016llX\n", ContextRecord->R10);

	printf("RDX %016llX ", ContextRecord->Rdx);
	printf("R11 %016llX\n", ContextRecord->R11);

	printf("RBP %016llX ", ContextRecord->Rbp);
	printf("R12 %016llX\n", ContextRecord->R12);

	printf("RSP %016llX ", ContextRecord->Rsp);
	printf("R13 %016llX\n", ContextRecord->R13);

	printf("RSI %016llX ", ContextRecord->Rsi);
	printf("R14 %016llX\n", ContextRecord->R14);

	printf("RDI %016llX ", ContextRecord->Rdi);
	printf("R15 %016llX\n", ContextRecord->R15);

	printf("\n");
	printf("RIP %016llX\n", ContextRecord->Rip);
	printf("\n");

	if (ContextRecord->Rip != 0) {
		printf("PROGRAM:\n");
		printf("%016llX", (ULONG_PTR)ContextRecord->Rip);

		unsigned char * code = (unsigned char*)ContextRecord->Rip;
		for (int x = 0; x < 16; x++) {
			printf(" %02X", code[x]);
		}
		printf("\n\n");
	}

	if (ContextRecord->Rsp != 0) {
		printf("STACK:\n");
		for (int x = 0; x < 16; x++) {
			ULONG_PTR * temp = (ULONG_PTR *)ContextRecord->Rsp + x;
			printf("%016llX %016llX\n", (ULONG_PTR)temp, *temp);
		}
	}
#endif

#ifdef WIN_X86
	printf("EAX %08lX\n", ContextRecord->Eax);
	printf("EBX %08lX\n", ContextRecord->Ebx);
	printf("ECX %08lX\n", ContextRecord->Ecx);
	printf("EDX %08lX\n", ContextRecord->Edx);
	printf("EBP %08lX\n", ContextRecord->Ebp);
	printf("ESP %08lX\n", ContextRecord->Esp);
	printf("ESI %08lX\n", ContextRecord->Esi);
	printf("EDI %08lX\n", ContextRecord->Edi);

	printf("\n");
	printf("EIP %08lX\n", ContextRecord->Eip);
	printf("\n");

	if (ContextRecord->Eip != 0) {
		printf("PROGRAM:\n");
		printf("%08lX", (ULONG_PTR)ContextRecord->Eip);

		unsigned char * code = (unsigned char*)ContextRecord->Eip;
		for (int x = 0; x < 16; x++) {
			printf(" %02X", code[x]);
		}
		printf("\n\n");
	}

	if (ContextRecord->Esp != 0) {
		printf("STACK:\n");
		for (int x = 0; x < 16; x++) {
			ULONG_PTR * temp = (ULONG_PTR *)ContextRecord->Esp + x;
			printf("%08lX %08lX\n", (ULONG_PTR)temp, *temp);
		}
	}
#endif
	ExitProcess(0);
}


int main(int argc, char * argv[]) {
	/* check or args */
	if (argc != 2) {
		printf("USAGE: %s <file.bin>\n", argv[0]);
		printf("\nSimple Loader 4 (Pointer Patching):\n\n");

		#ifdef WIN_X64
			printf("GMH=%016llx\n", rev64((ULONG_PTR)GetModuleHandle));
			printf("GPA=%016llx\n", rev64((ULONG_PTR)GetProcAddress));
		#else
			printf("GMH=%08lx\n", htonl((DWORD)GetModuleHandle));
			printf("GPA=%08lx\n", htonl((DWORD)GetProcAddress));
		#endif

		/* print out our envkey with little endian-byte order. */
		DWORD serialNoRev = htonl(GetVolSerialNo());

		printf("\nSimple Loader 5 (Execution Guardrails):\n\n");
		printf("ENVKEY=%08lx%08lx\n", serialNoRev, serialNoRev);

		return 0;
	}

	/* continue on! */
	HANDLE hFile;
	char * file = argv[1];
	char * data;
	DWORD  fileSz;
	DWORD  read;

	/* open the file for reading */
	hFile = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Unable to open %s for read: %ld", file, GetLastError());
		return 0;
	}

	/* get our file size */
	fileSz = GetFileSize(hFile, NULL);
	if (fileSz == INVALID_FILE_SIZE) {
		printf("Invalid file size for %s: %ld", file, GetLastError());
		goto end;
	}

	/* allocate the right amount of memory */
	data = (char *)VirtualAlloc(NULL, fileSz, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Allocated 0x%p (%ld bytes) for PIC\n", data, fileSz);

	/* read the file */
	if (!ReadFile(hFile, data, fileSz, &read, NULL)) {
		printf("Read %ld bytes from %s failed: %ld", fileSz, file, GetLastError());
		goto end;
	}

	/* check the result */
	if (fileSz != read) {
		printf("Read %ld bytes of %ld from %s. Incomplete!", read, fileSz, file);
		goto end;
	}

	/* give user a chance to attach a debugger */
	printf("Read %ld bytes from %s. Press 'enter' to continue.\n", fileSz, file);

	/* wait! */
	getchar();

	/* No debugger? I will become the debugger */
	if (!IsDebuggerPresent())
		AddVectoredExceptionHandler(FALSE, CrashHandler);

	/* ready? */
	( (void (*)())data )();

end:
	CloseHandle(hFile);
	return 0;
}
