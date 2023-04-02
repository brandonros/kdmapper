#include <ntddk.h>
#include "shared.h"

NTSTATUS CustomDriverEntry(
	_In_ PDRIVER_OBJECT  kdmapperParam1,
	_In_ PUNICODE_STRING kdmapperParam2
)
{
	UNREFERENCED_PARAMETER(kdmapperParam1);
	UNREFERENCED_PARAMETER(kdmapperParam2);
	
	DbgPrintEx(0, 0, "Hello world!");

	Smbios::ChangeSmbiosSerials();

	return 0;
}