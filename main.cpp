#include "log.h"
#include "imports.h"


#define pooltag 'dEad'
extern void NTAPI server_thread(void*);
#define xorstr_(x) x
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr) + (DWORD)(addValue))
uintptr_t get_kerneladdr(const char* name, size_t& size) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, pooltag);

	if (!pModuleList) {
		DbgPrint("ExAllocatePoolWithTag failed(kernel addr)\n");
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePoolWithTag(pModuleList, pooltag);

	return address;
}
template <typename t = void*>
t find_pattern(void* start, size_t length, const char* pattern, const char* mask) {
	const auto data = static_cast<const char*>(start);
	const auto pattern_length = strlen(mask);

	for (size_t i = 0; i <= length - pattern_length; i++)
	{
		bool accumulative_found = true;

		for (size_t j = 0; j < pattern_length; j++)
		{
			if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
			{
				accumulative_found = false;
				break;
			}

			if (data[i + j] != pattern[j] && mask[j] != '?')
			{
				accumulative_found = false;
				break;
			}
		}

		if (accumulative_found)
		{
			return (t)(reinterpret_cast<uintptr_t>(data) + i);
		}
	}

	return (t)nullptr;
}
uintptr_t dereference(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

void clean_unloaded_drivers() {

	ULONG bytes = 0;
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, pooltag);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwQuerySystemInformation failed(unloaded drivers)\n");
		ExFreePoolWithTag(modules, pooltag);
		return;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t ntoskrnlBase = 0;
	size_t ntoskrnlSize = 0;

	ntoskrnlBase = get_kerneladdr("ntoskrnl.exe", ntoskrnlSize);

	ExFreePoolWithTag(modules, pooltag);

	if (ntoskrnlBase <= 0) {
		DbgPrint("get failed(unloaded drivers)\n");
		return;
	}

	// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3 + current signature address = MmUnloadedDrivers
	auto mmUnloadedDriversPtr = find_pattern<uintptr_t>((void*)ntoskrnlBase, ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");


	if (!mmUnloadedDriversPtr) {
		DbgPrint("unload equals 0(unloaded drivers)\n");
		return;
	}

	uintptr_t mmUnloadedDrivers = dereference(mmUnloadedDriversPtr, 3);

	memset(*(uintptr_t**)mmUnloadedDrivers, 0, 0x7D0);
}
NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER;
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}
NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
{
	//ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER
	size_t ntoskrnlSize = 0;
	if (nullptr == base)
		base = (PVOID)get_kerneladdr("ntoskrnl.exe", ntoskrnlSize);
	if (base == nullptr)
		return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr);
				return status;
			}
		}
	}

	return STATUS_ACCESS_DENIED;
}
PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}
extern "C" bool LocatePiDDB(PRTL_AVL_TABLE * table)
{
	UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";
	PVOID PiDDBCacheTablePtr = nullptr;

	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
		//DbgPrintEx(0, 0, xorstr_("Unable to find PiDDBCacheTablePtr sig.\n"));
		return false;
	}

	PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return true;
}

void clean_piddb_cache() {
	PRTL_AVL_TABLE PiDDBCacheTable;
	LocatePiDDB(&PiDDBCacheTable);

	//DbgPrintEx(0, 0, "[]PiDDBCacheTable: %d\n", PiDDBCacheTable);
	uintptr_t entry_address = uintptr_t(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);
	//DbgPrint("entry_address: %d\n", entry_address);

	PiDDBCacheEntry* entry = (PiDDBCacheEntry*)(entry_address);

	if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3) {
		
		entry->TimeDateStamp = 0x54EAC3;
		entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
	}

	ULONG count = 0;
	for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
	{
		PiDDBCacheEntry* cache_entry = (PiDDBCacheEntry*)(link);

		//DbgPrintEx(0,0 , "cache_entry count: %lu name: %wZ \t\t stamp: %x\n", count, cache_entry->DriverName, cache_entry->TimeDateStamp);

		if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3) {
			cache_entry->TimeDateStamp = 0x54EAC4 + count;
			cache_entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
			DbgPrintEx(0,0,"Found ");
		}
	}
}

extern "C" NTSTATUS DriverEntry(
	PDRIVER_OBJECT  driver_object,
	PUNICODE_STRING registry_path
)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	HANDLE thread_handle = nullptr;
	const auto status = PsCreateSystemThread(
		&thread_handle,
		GENERIC_ALL,
		nullptr,
		nullptr,
		nullptr,
		server_thread,
		nullptr
	);

	if (!NT_SUCCESS(status))
	{
		log("Failed to create server thread. Status code: %X.", status);
		clean_unloaded_drivers();
		clean_piddb_cache();
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(thread_handle);
	clean_unloaded_drivers();
	clean_piddb_cache();
	return STATUS_SUCCESS;
	
}