#include "server_shared.h"
#include "sockets.h"
#include "imports.h"

#include <ntstrsafe.h>
#include "log.h"

static uint64_t handle_copy_memory(const PacketCopyMemory& packet)
{
	PEPROCESS dest_process = nullptr;
	PEPROCESS src_process  = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.dest_process_id), &dest_process)))
	{
		return uint64_t(STATUS_INVALID_CID);
	}

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.src_process_id), &src_process)))
	{
		ObDereferenceObject(dest_process);
		return uint64_t(STATUS_INVALID_CID);
	}

	SIZE_T   return_size = 0;
	NTSTATUS status = MmCopyVirtualMemory(
		src_process,
		(void*)packet.src_address,
		dest_process,
		(void*)packet.dest_address,
		packet.size,
		UserMode,
		&return_size
	);

	ObDereferenceObject(dest_process);
	ObDereferenceObject(src_process);

	return uint64_t(status);
}
static uint64_t handle_get_base_address(const PacketGetBaseAddress& packet)
{
	PEPROCESS pProcess = NULL;
	UNICODE_STRING se;
	if (packet.name == 0) {
		RtlInitUnicodeString(&se, L"UnityPlayer.dll");
	}
	else {
		RtlInitUnicodeString(&se, L"GameAssembly.dll");
	}
	uint64_t result = 0;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)packet.process_id, &pProcess)))
	{
		PPEB pPeb = PsGetProcessPeb(pProcess);
		KAPC_STATE state;

		KeStackAttachProcess(pProcess, &state);

		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; result == 0 && pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &se, TRUE) == 0) {
				result = (uint64_t)pEntry->DllBase;
			}
		}

		KeUnstackDetachProcess(&state);
	}
	return result;
}

uint64_t handle_incoming_packet(const Packet& packet)
{
	switch (packet.header.type)
	{
	case PacketType::packet_copy_memory:
		return handle_copy_memory(packet.data.copy_memory);

	case PacketType::packet_get_base_address:
		return handle_get_base_address(packet.data.get_base_address);

	default:
		break;
	}

	return uint64_t(STATUS_NOT_IMPLEMENTED);
}

bool complete_request(const SOCKET client_connection, const uint64_t result)
{
	Packet packet{ };

	packet.header.magic				= packet_magic;
	packet.header.type				= PacketType::packet_completed;
	packet.data.completed.result	= result;

	return send(client_connection, &packet, sizeof(packet), 0) != SOCKET_ERROR;
}