#include <ntddk.h>
#include "hk.h"
#include "shared.h"

PFNFTH pOriginalWmipRawSMBiosTableHandler = NULL;

NTSTATUS(*OriginalWmipRawSMBiosTableHandler)(PSYSTEM_FIRMWARE_TABLE_INFORMATION pTableInformation);

NTSTATUS __cdecl WmipRawSMBiosTableHandlerHook(
	PSYSTEM_FIRMWARE_TABLE_INFORMATION pTableInformation
)
{
	NTSTATUS status = pOriginalWmipRawSMBiosTableHandler(pTableInformation);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	auto TableLength = [](SMBIOS_HEADER* pHeader) -> size_t
	{
		char* current = reinterpret_cast<char*>(pHeader) + pHeader->Length;
		size_t i = 1;

		for (i; current[i - 1] != '\0' || current[i] != '\0'; i++)
		{
			// Scan until we find a double zero byte
		}

		return pHeader->Length + i + 1;
	};

	auto GetString = [](SMBIOS_HEADER* pHeader, UCHAR id) -> char*
	{
		char* string = reinterpret_cast<char*>(pHeader) + pHeader->Length;

		for (UINT16 i = 1; i < id; i++)
		{
			string += strlen(string) + 1;
		}

		return string;
	};

	auto* pHeader = reinterpret_cast<SMBIOS_HEADER*>(pTableInformation->TableBuffer);

	while (reinterpret_cast<UINT64>(pHeader) < (reinterpret_cast<UINT64>(pTableInformation->TableBuffer) + pTableInformation->TableBufferLength))
	{
		char* serialNumber = NULL;

		if (pHeader->Type == 1) // SystemInfo
		{
			auto* pSystemInfoHeader = reinterpret_cast<SMBIOS_TYPE1*>(pHeader);

			serialNumber = GetString((SMBIOS_HEADER*)pSystemInfoHeader, pSystemInfoHeader->SerialNumber);
		}
		else if (pHeader->Type == 2) // BaseBoard
		{
			auto* pBaseBoardHeader = reinterpret_cast<SMBIOS_TYPE2*>(pHeader);

			serialNumber = GetString((SMBIOS_HEADER*)pBaseBoardHeader, pBaseBoardHeader->SerialNumber);
		}

		if (serialNumber)
		{
			// TODO
			DbgPrintEx(0, 0, "type = %d serialNumber = %s\n", pHeader->Type, serialNumber);
		}

		pHeader = reinterpret_cast<SMBIOS_HEADER*>(reinterpret_cast<UCHAR*>(pHeader) + TableLength(pHeader));
	}

	return status;
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrintEx(0, 0, "DriverUnload\n");

	//HkRestoreFunction((PVOID)pOriginalWmipRawSMBiosTableHandler, (PVOID)OriginalWmipRawSMBiosTableHandler);
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  kdmapperParam1,
	_In_ PUNICODE_STRING kdmapperParam2
)
{
	UNREFERENCED_PARAMETER(kdmapperParam1);
	UNREFERENCED_PARAMETER(kdmapperParam2);
	
	DbgPrintEx(0, 0, "DriverEntry\n");

	//Smbios::ChangeSmbiosSerials();

	auto* base = Utils::GetModuleBase("ntoskrnl.exe");
	if (!base)
	{
		DbgPrintEx(0, 0, "Failed to find ntoskrnl.sys base!\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "base = %p\n", base);

	pOriginalWmipRawSMBiosTableHandler = (PFNFTH)Utils::FindPatternImage(base, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x3e\xd5\x3f\x00\x8b\xd0\xb8\x23\x00\x00\xc0", "?????????????????????????????????????????????????????xxxxxxxxxxxx"); // ntoskrnl.exe WmipRawSMBiosTableHandler
	if (!pOriginalWmipRawSMBiosTableHandler)
	{
		DbgPrintEx(0, 0, "Failed to find pOriginalWmipRawSMBiosTableHandler!\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "pOriginalWmipRawSMBiosTableHandler = %p\n", pOriginalWmipRawSMBiosTableHandler);

	NTSTATUS hookResult = HkDetourFunction((PVOID)pOriginalWmipRawSMBiosTableHandler, (PVOID)WmipRawSMBiosTableHandlerHook, 18, (PVOID*)&OriginalWmipRawSMBiosTableHandler);
	if (!hookResult) {
		DbgPrintEx(0, 0, "Failed to HkDetourFunction!\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "entry success!\n");

	return 0;
}