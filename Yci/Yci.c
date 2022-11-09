#include "SomeStruct.h"

PVOID SearchOPcode(PDRIVER_OBJECT pObj, PWCHAR DriverName, PCHAR sectionName, PUCHAR opCode, int len, int offset)
{
	PVOID dllBase = NULL;
	UNICODE_STRING uniDriverName;
	PKLDR_DATA_TABLE_ENTRY firstentry;
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pObj->DriverSection;

	firstentry = entry;
	RtlInitUnicodeString(&uniDriverName, DriverName);
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry) 
	{
		if (entry->FullDllName.Buffer != 0 && entry->BaseDllName.Buffer != 0)
		{
			if (RtlCompareUnicodeString(&uniDriverName, &(entry->BaseDllName), FALSE) == 0)
			{
				dllBase = entry->DllBase;
				break;
			}
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	if (dllBase)
	{
		__try 
		{
			PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)dllBase;
			if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return NULL;
			}
			PIMAGE_NT_HEADERS64 pImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + ImageDosHeader->e_lfanew);
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pImageNtHeaders64 + sizeof(pImageNtHeaders64->Signature) + sizeof(pImageNtHeaders64->FileHeader) + pImageNtHeaders64->FileHeader.SizeOfOptionalHeader);
			
			PUCHAR endAddress = 0;
			PUCHAR starAddress = 0;
			for (int i = 0; i < pImageNtHeaders64->FileHeader.NumberOfSections; i++)
			{
				if (memcmp(sectionName, pSectionHeader->Name, strlen(sectionName) + 1) == 0)
				{
					starAddress = pSectionHeader->VirtualAddress + (PUCHAR)dllBase;
					endAddress = pSectionHeader->VirtualAddress + (PUCHAR)dllBase + pSectionHeader->SizeOfRawData;
					break;
				}
				pSectionHeader++;
			}
			if (endAddress && starAddress)
			{
				for (; starAddress < endAddress - len - 1; starAddress++)
				{
					if (MmIsAddressValid(starAddress))
					{
						int i = 0;
						for (; i < len; i++)
						{
							if (opCode[i] == 0x2a)
								continue;
							if (opCode[i] != starAddress[i])
								break;
						}
						if (i == len)
						{
							return starAddress + offset;
						}
					}
				}
			}
		}__except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	return NULL;
}

NTSTATUS initFunc(PDRIVER_OBJECT pObj)
{
	UCHAR suspendOpCodeWin7[] = { 0x4C,0x8B,0xEA,0x48,0x8B,0xF1,0x33,0xFF,0x89,0x7C,'*','*',0x65,
		'*','*','*','*','*','*','*','*',0x4C,0x89,'*','*','*','*','*','*',0x66,0x41,'*','*','*',
		'*','*','*','*',0x48,'*','*','*','*','*','*',0x0F,'*','*',0x48,0x8B,0x01 };
	UCHAR suspendOpCodeWin10[] = { 0x48,0x83,0xEC,'*',0x4C,0x8B,'*',0x48,0x8B,0xF9,0x83,0x64,0x24,
		0x20,'*',0x65,0x48,0x8B,0x34,0x25,0x88,0x01,0x00,'*',0x48,0x89,0x74,0x24,0x70 };
	g_PsSuspendThread = (PPsSuspendThread)SearchOPcode(pObj, L"ntoskrnl.exe", "PAGE", suspendOpCodeWin7, sizeof(suspendOpCodeWin7), -21);
	if (!g_PsSuspendThread)
	{
		g_PsSuspendThread = (PPsSuspendThread)SearchOPcode(pObj, L"ntoskrnl.exe", "PAGE", suspendOpCodeWin10, sizeof(suspendOpCodeWin10), -17);
		if(!g_PsSuspendThread)
			return STATUS_UNSUCCESSFUL;
	}

	UCHAR resumeOpCode1[] = { 0x40,0x53,0x48,'*','*','*',0x48,0x8B,0xDA,0xE8,'*','*','*','*',0x48,
		0x85,0xDB,0x74,'*',0x89,0x03,0x33,0xC0,0x48,'*','*','*',0x5B,0xC3 };
	UCHAR resumeOpCode2[] = { 0xFF,0xF3,0x48,'*','*','*',0x48,0x8B,0xDA,0xE8,'*','*','*','*',0x48,
		0x85,0xDB,0x74,'*',0x89,0x03,0x33,0xC0,0x48,'*','*','*',0x5B,0xC3 };
	UCHAR resumeOpCode3[] = { 0x48,0x83,0xEC,'*',0x48,0x8B,0xDA,0x48,0x8B,0xF9,0xE8,'*','*','*',
		'*',0x65,0x48,0x8B,0x14,0x25,'*','*','*','*',0x8B,0xF0,0x83,0xF8,0x01 };
	UCHAR resumeOpCode4[] = { 0x48,0x89,0x54,'*','*',0x48,0x89,'*','*','*',0x53,0x56,0x57,0x41,
		0x56,0x41,0x57 };

	g_PsResumeThread = (PPsResumeThread)SearchOPcode(pObj, L"ntoskrnl.exe", "PAGE", resumeOpCode1, sizeof(resumeOpCode1), 0);
	if (!g_PsResumeThread)
	{
		g_PsResumeThread = (PPsResumeThread)SearchOPcode(pObj, L"ntoskrnl.exe", "PAGE", resumeOpCode2, sizeof(resumeOpCode2), 0);
		if (!g_PsResumeThread)
		{
			g_PsResumeThread = (PPsResumeThread)SearchOPcode(pObj, L"ntoskrnl.exe", "PAGE", resumeOpCode3, sizeof(resumeOpCode3), -11);
			if (!g_PsResumeThread)
			{
				g_PsResumeThread = (PPsResumeThread)SearchOPcode(pObj, L"ntoskrnl.exe", "PAGE", resumeOpCode4, sizeof(resumeOpCode4), 0);
				if (!g_PsResumeThread)
				{
					return STATUS_UNSUCCESSFUL;
				}
			}
		}
	}

	UNICODE_STRING ZwGetNextThreadString = RTL_CONSTANT_STRING(L"ZwGetNextThread");
	g_ZwGetNextThread = (PZwGetNextThread)MmGetSystemRoutineAddress(&ZwGetNextThreadString);
	if (!g_ZwGetNextThread)
	{
		UNICODE_STRING ZwGetNotificationResourceManagerString = RTL_CONSTANT_STRING(L"ZwGetNotificationResourceManager");
		PUCHAR ZwGetNotificationResourceManager = (PUCHAR)MmGetSystemRoutineAddress(&ZwGetNotificationResourceManagerString);
		if (ZwGetNotificationResourceManager)
		{
			PUCHAR starAddress = ZwGetNotificationResourceManager - 78;
			for(; starAddress < ZwGetNotificationResourceManager - 8; starAddress++)
			{
				if (starAddress[0] == 0x48 && starAddress[1] == 0x8B && starAddress[2] == 0xC4)
				{
					g_ZwGetNextThread = (PZwGetNextThread)starAddress;
					break;
				}	
			}
		}
		if(!g_ZwGetNextThread)
			return STATUS_UNSUCCESSFUL;
	}
		
	UNICODE_STRING PsGetThreadTebString = RTL_CONSTANT_STRING(L"PsGetThreadTeb");
	g_PsGetThreadTeb = (PPsGetThreadTeb)MmGetSystemRoutineAddress(&PsGetThreadTebString);
	if (!g_PsGetThreadTeb)
		return STATUS_UNSUCCESSFUL;

	UNICODE_STRING PsGetProcessWow64ProcessString = RTL_CONSTANT_STRING(L"PsGetProcessWow64Process");
	g_PsGetProcessWow64Process = (PPsGetProcessWow64Process)MmGetSystemRoutineAddress(&PsGetProcessWow64ProcessString);
	if (!g_PsGetProcessWow64Process)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

PINJECT_BUFFER GetNativeCode(PVOID LdrLoadDll, PUNICODE_STRING DllFullPath, ULONGLONG orgEip)
{
	SIZE_T Size = PAGE_SIZE;
	PINJECT_BUFFER InjectBuffer = NULL;
	UCHAR Code[] = {
		0x41, 0x57,                             // push r15
		0x41, 0x56,                             // push r14
		0x41, 0x55,                             // push r13
		0x41, 0x54,                             // push r12
		0x41, 0x53,                             // push r11
		0x41, 0x52,                             // push r10
		0x41, 0x51,                             // push r9
		0x41, 0x50,                             // push r8
		0x50,                                   // push rax
		0x51,                                   // push rcx
		0x53,                                   // push rbx
		0x52,                                   // push rdx
		0x55,                                   // push rbp
		0x54,                                   // push rsp
		0x56,                                   // push rsi
		0x57,                                   // push rdi
		0x66, 0x9C,                             // pushf
		0x48, 0x83, 0xEC, 0x26,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +38
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +48
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +58
		0xFF, 0xD0,                             // call rax
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +70
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +86
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x26,                 // add rsp, 0x28
		0x66, 0x9D,                             // popf
		0x5F,                                   // pop rdi
		0x5E,                                   // pop rsi 
		0x5C,                                   // pop rsp
		0x5D,                                   // pop rbp
		0x5A,                                   // pop rdx
		0x5B,                                   // pop rbx
		0x59,                                   // pop rcx
		0x58,                                   // pop rax
		0x41, 0x58,                             // pop r8
		0x41, 0x59,                             // pop r9
		0x41, 0x5A,                             // pop r10
		0x41, 0x5B,                             // pop r11
		0x41, 0x5C,                             // pop r12
		0x41, 0x5D,                             // pop r13
		0x41, 0x5E,                             // pop r14
		0x41, 0x5F,                             // pop r15
		0x50,                                   // push rax
		0x50,                                   // push rax 
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, orgEip offset +130
		0x48, 0x89, 0x44, 0x24, 0x08,           // mov [rsp+8],rax
		0x58,                                   // pop rax
		0xC3                                    // ret
	};

	if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), &InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		PUNICODE_STRING UserPath = &InjectBuffer->Path;
		UserPath->Length = DllFullPath->Length;
		UserPath->MaximumLength = DllFullPath->MaximumLength;
		UserPath->Buffer = InjectBuffer->Buffer;

		RtlUnicodeStringCopy(UserPath, DllFullPath);

		memcpy(InjectBuffer, Code, sizeof(Code));

		*(ULONGLONG*)((PUCHAR)InjectBuffer + 38) = (ULONGLONG)UserPath;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 48) = (ULONGLONG)& InjectBuffer->ModuleHandle;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 58) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 70) = (ULONGLONG)& InjectBuffer->Complete;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 86) = (ULONGLONG)& InjectBuffer->Status;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 130) = orgEip;

		return InjectBuffer;
	}
	return NULL;
}

PINJECT_BUFFER GetWow64Code(PVOID LdrLoadDll, PUNICODE_STRING DllFullPath, ULONG orgEip)
{
	SIZE_T Size = PAGE_SIZE;
	PINJECT_BUFFER InjectBuffer = NULL;

	UCHAR Code[] = {
		0x60,                                   // pushad
		0x9c,                                   // pushfd
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +3 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +8
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +17
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +22
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +33
		0x89, 0x02,                             // mov [edx], eax
		0x9d,                                   // popfd
		0x61,                                   // popad
		0x50,                                   // push eax
		0x50,                                   // push eax
		0xb8, 0, 0, 0, 0,                       // mov eax, orgEip
		0x89, 0x44, 0x24, 0x04,                 // mov [esp+4],eax
		0x58,                                   // pop eax
		0xc3                                    // ret
	};

	if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), &InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		PUNICODE_STRING32 pUserPath = &InjectBuffer->Path32;
		pUserPath->Length = DllFullPath->Length;
		pUserPath->MaximumLength = DllFullPath->MaximumLength;
		pUserPath->Buffer = (ULONG)(ULONG_PTR)InjectBuffer->Buffer;

		memcpy((PVOID)pUserPath->Buffer, DllFullPath->Buffer, DllFullPath->Length);

		memcpy(InjectBuffer, Code, sizeof(Code));

		*(ULONG*)((PUCHAR)InjectBuffer + 3) = (ULONG)(ULONG_PTR)& InjectBuffer->ModuleHandle;
		*(ULONG*)((PUCHAR)InjectBuffer + 8) = (ULONG)(ULONG_PTR)pUserPath;
		*(ULONG*)((PUCHAR)InjectBuffer + 17) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)InjectBuffer + 17) - 5 + 1);
		*(ULONG*)((PUCHAR)InjectBuffer + 22) = (ULONG)(ULONG_PTR)& InjectBuffer->Complete;
		*(ULONG*)((PUCHAR)InjectBuffer + 33) = (ULONG)(ULONG_PTR)& InjectBuffer->Status;
		*(ULONG*)((PUCHAR)InjectBuffer + 44) = orgEip;
		return InjectBuffer;
	}

	return NULL;
}

NTSTATUS SetThreadStartAddress(PETHREAD pEthread,BOOLEAN isWow64, PVOID LdrLoadDll, PUNICODE_STRING DllFullPath, PINJECT_BUFFER *allcateAddress)
{
	__try
	{
		if (isWow64)
		{
			PVOID pTeb = g_PsGetThreadTeb(pEthread);
			if (pTeb)
			{
				PWOW64_CONTEXT  pCurrentContext = (PWOW64_CONTEXT)(*(ULONG64*)((ULONG64)pTeb + WOW64CONTEXTOFFSET));
				ProbeForRead((PVOID)pCurrentContext, sizeof(pCurrentContext), sizeof(CHAR));
				PINJECT_BUFFER newAddress = GetWow64Code(LdrLoadDll, DllFullPath, pCurrentContext->Eip);
				if (newAddress)
				{
					newAddress->orgRipAddress = (ULONG64) & (pCurrentContext->Eip);
					newAddress->orgRip = pCurrentContext->Eip;
					*allcateAddress = newAddress;
					pCurrentContext->Eip = (ULONG)(ULONG64)(newAddress);
				}
				return STATUS_SUCCESS;
			}
		}
		else
		{
			if (MmIsAddressValid((PVOID) * (ULONG64*)((ULONG64)pEthread + INITIALSTACKOFFSET)))
			{
				PKTRAP_FRAME pCurrentTrap = (PKTRAP_FRAME)(*(ULONG64*)((ULONG64)pEthread + INITIALSTACKOFFSET) - sizeof(KTRAP_FRAME));
				PINJECT_BUFFER newAddress = GetNativeCode(LdrLoadDll, DllFullPath, pCurrentTrap->Rip);
				if (newAddress)
				{
					newAddress->orgRipAddress = (ULONG64) & (pCurrentTrap->Rip);
					newAddress->orgRip = pCurrentTrap->Rip;
					*allcateAddress = newAddress;
					pCurrentTrap->Rip = (ULONG64)newAddress;
				}
			}
			return STATUS_SUCCESS;
		}
	}__except (EXCEPTION_EXECUTE_HANDLER) {}

	return STATUS_UNSUCCESSFUL;
}

PVOID GetUserModule(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN IsWow64) 
{
	if (EProcess == NULL)
		return NULL;
	__try 
	{
		if (IsWow64) 
		{
			PPEB32 Peb32 = (PPEB32)g_PsGetProcessWow64Process(EProcess);
			if (Peb32 == NULL) 
				return NULL;

			if (!Peb32->Ldr)
				return NULL;

			for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
				ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
				ListEntry = (PLIST_ENTRY32)ListEntry->Flink) 
			{
				UNICODE_STRING UnicodeString;
				PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
				RtlUnicodeStringInit(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);
				if (RtlCompareUnicodeString(&UnicodeString, ModuleName, TRUE) == 0)
					return (PVOID)LdrDataTableEntry32->DllBase;
			}
		}
		else 
		{
			PPEB Peb = PsGetProcessPeb(EProcess);
			if (!Peb)
				return NULL;

			if (!Peb->Ldr)
				return NULL;

			for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
				ListEntry != &Peb->Ldr->InLoadOrderModuleList;
				ListEntry = ListEntry->Flink) 
			{
				PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, ModuleName, TRUE) == 0)
					return LdrDataTableEntry->DllBase;
			}
		}
	}__except (EXCEPTION_EXECUTE_HANDLER){}

	return NULL;
}

PVOID GetModuleExport(IN PVOID ModuleBase, IN PCCHAR FunctionName)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS32 ImageNtHeaders32 = NULL;
	PIMAGE_NT_HEADERS64 ImageNtHeaders64 = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
	ULONG ExportDirectorySize = 0;
	ULONG_PTR FunctionAddress = 0;

	if (ModuleBase == NULL)
		return NULL;

	__try
	{
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
		ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);

		if (ImageNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
			ExportDirectorySize = ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}
		else
		{
			ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
			ExportDirectorySize = ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}

		PUSHORT pAddressOfOrds = (PUSHORT)(ImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)ModuleBase);
		PULONG  pAddressOfNames = (PULONG)(ImageExportDirectory->AddressOfNames + (ULONG_PTR)ModuleBase);
		PULONG  pAddressOfFuncs = (PULONG)(ImageExportDirectory->AddressOfFunctions + (ULONG_PTR)ModuleBase);

		for (ULONG i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
		{
			USHORT OrdIndex = 0xFFFF;
			PCHAR  pName = NULL;

			if ((ULONG_PTR)FunctionName <= 0xFFFF)
			{
				OrdIndex = (USHORT)i;
			}

			else if ((ULONG_PTR)FunctionName > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
			{
				pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)ModuleBase);
				OrdIndex = pAddressOfOrds[i];
			}

			else
				return NULL;
			if (((ULONG_PTR)FunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)FunctionName) == OrdIndex + ImageExportDirectory->Base) ||
				((ULONG_PTR)FunctionName > 0xFFFF && strcmp(pName, FunctionName) == 0))
			{
				FunctionAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)ModuleBase;
				break;
			}
		}
	}__except(EXCEPTION_EXECUTE_HANDLER){}

	return (PVOID)FunctionAddress;
}

NTSTATUS InjectProcess(ULONG pid, PUNICODE_STRING DllFullPath, PINJECT_BUFFER* allcateAddress)
{
	PEPROCESS pEprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pEprocess)))
	{
		KAPC_STATE kApc = { 0 };
		KeStackAttachProcess(pEprocess, &kApc);
		UNICODE_STRING ntdllString = RTL_CONSTANT_STRING(L"Ntdll.dll");
		PVOID NtdllAddress = GetUserModule(pEprocess, &ntdllString, g_PsGetProcessWow64Process(pEprocess) != 0);
		if (!NtdllAddress)
		{
			KeUnstackDetachProcess(&kApc);
			ObDereferenceObject(pEprocess);
			return STATUS_UNSUCCESSFUL;
		}
		
		PVOID LdrLoadDll = GetModuleExport(NtdllAddress, "LdrLoadDll");
		if (!LdrLoadDll)
		{
			KeUnstackDetachProcess(&kApc);
			ObDereferenceObject(pEprocess);
			return STATUS_UNSUCCESSFUL;
		}

		HANDLE threadHandle = NULL;
		if(NT_SUCCESS(g_ZwGetNextThread((HANDLE)-1, (HANDLE)0, 0x1FFFFF, 0x240, 0, &threadHandle)))
		{
			PVOID threadObj = NULL;
			NTSTATUS state = ObReferenceObjectByHandle(threadHandle, 0x1FFFFF, *PsThreadType, KernelMode, &threadObj, NULL);
			if (NT_SUCCESS(state))
			{
				g_PsSuspendThread(threadObj,NULL);
				SetThreadStartAddress(threadObj, g_PsGetProcessWow64Process(pEprocess) != 0,LdrLoadDll,DllFullPath, allcateAddress);
				g_PsResumeThread(threadObj,NULL);
				ObDereferenceObject(threadObj);
			}
			NtClose(threadHandle);
		}
		KeUnstackDetachProcess(&kApc);
		ObDereferenceObject(pEprocess);
	}
	return STATUS_SUCCESS;
}

VOID Sleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

VOID freeMemory(PVOID Parameter)
{
	ULONG counts = 0;
	SIZE_T Size = PAGE_SIZE;
	PEPROCESS pEprocess = NULL;
	PFREEADDRESS freeAdd = (PFREEADDRESS)Parameter;
	
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(freeAdd->pid), &pEprocess)))
	{
		KAPC_STATE kApc = { 0 };
		while (TRUE)
		{
			KeStackAttachProcess(pEprocess, &kApc);
			__try 
			{
				ProbeForRead((PVOID)freeAdd->allcateAddress,sizeof(freeAdd->allcateAddress),sizeof(CHAR));
				if (freeAdd->allcateAddress->Complete || counts > MAXCOUNTS)
				{
					if (counts > MAXCOUNTS)
					{
						if (g_PsGetProcessWow64Process(pEprocess) != 0)
						{
							ProbeForRead((PVOID)freeAdd->allcateAddress->orgRipAddress, sizeof(freeAdd->allcateAddress->orgRipAddress), sizeof(CHAR));
							*(ULONG*)freeAdd->allcateAddress->orgRipAddress = (ULONG)freeAdd->allcateAddress->orgRip;
						}
						else
						{
							if(MmIsAddressValid((PVOID)freeAdd->allcateAddress->orgRipAddress))
								*(ULONG64*)freeAdd->allcateAddress->orgRipAddress = (ULONG64)freeAdd->allcateAddress->orgRip;
						}
					}
					ZwFreeVirtualMemory((HANDLE)-1, (PVOID)& freeAdd->allcateAddress, &Size, MEM_DECOMMIT);
					break;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) 
			{
				break;
			}
			KeUnstackDetachProcess(&kApc);
			Sleep(MSEC);
			counts++;
		}
		KeUnstackDetachProcess(&kApc);
		ObDereferenceObject(pEprocess);
	}

	ExFreePool(freeAdd);
	freeAdd = NULL;
	g_gameOver = TRUE;
}

NTSTATUS freeAddress(PFREEADDRESS freeAdd)
{
	g_workItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 'Yci');
	if (g_workItem)
	{
		ExInitializeWorkItem(g_workItem, freeMemory, freeAdd);
		ExQueueWorkItem(g_workItem, DelayedWorkQueue);
	}
	return STATUS_SUCCESS;
}

VOID  injectDll(ULONG pid, PUNICODE_STRING dllPath)
{
	PINJECT_BUFFER allcateAddress = NULL;
	InjectProcess(pid, dllPath, &allcateAddress);
	if (allcateAddress)
	{
		PFREEADDRESS freeAdd = (PFREEADDRESS)ExAllocatePoolWithTag(NonPagedPool, sizeof(FREEADDRESS), 'Yci');
		if (freeAdd)
		{
			freeAdd->pid = pid;
			freeAdd->allcateAddress = allcateAddress;
			freeAddress(freeAdd);
		}
	}
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pObj)
{
	UNREFERENCED_PARAMETER(pObj);
	while (!g_gameOver)
	{
		Sleep(MSEC);
		if (g_gameOver);
			break;
	}
		
	if (g_workItem)
	{
		ExFreePool(g_workItem);
		g_workItem = NULL;
	}
		
	DbgPrint("See you!\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pObj, PUNICODE_STRING pPath)
{
	UNREFERENCED_PARAMETER(pPath);
	//DbgBreakPoint();
	//win10
	UNICODE_STRING x86dll = RTL_CONSTANT_STRING(L"C:\\Users\\yongcai\\Desktop\\Yci.dll");
	UNICODE_STRING x64dll = RTL_CONSTANT_STRING(L"C:\\Users\\yongcai\\Desktop\\Ycix64.dll");

	//win7
	//UNICODE_STRING x86dll = RTL_CONSTANT_STRING(L"C:\\123\\Yci.dll");
	//UNICODE_STRING x64dll = RTL_CONSTANT_STRING(L"C:\\123\\Ycix64.dll");

	pObj->DriverUnload = DriverUnload;
	if (!NT_SUCCESS(initFunc(pObj)))
		DbgPrint("intit failed ! \n");

	injectDll(6636,&x64dll);
	
	return STATUS_SUCCESS;
}