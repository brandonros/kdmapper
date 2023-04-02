#include <ntddk.h>
#include "shared.h"

/**
 * \brief Get's the string from SMBIOS table
 * \param header Table header
 * \param string String itself
 * \return Pointer to the null terminated string
 */
char* Smbios::GetString(SMBIOS_HEADER* header, SMBIOS_STRING string)
{
    const auto* start = reinterpret_cast<const char*>(header) + header->Length;

    if (!string || *start == 0)
        return nullptr;

    while (--string)
    {
        start += strlen(start) + 1;
    }

    return const_cast<char*>(start);
}

/**
 * \brief Replace string at a given location by randomized string with same length
 * \param string Pointer to string (has to be null terminated)
 */
void Smbios::RandomizeString(char* string)
{
    const auto length = static_cast<int>(strlen(string));

    auto* buffer = static_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, length, POOL_TAG));
    if (!buffer) {
        DbgPrintEx(0, 0, "ExAllocatePoolWithTag failed\n");
        return;
    }

    Utils::RandomText(buffer, length);
    buffer[length] = '\0';

    memcpy(string, buffer, length);

    ExFreePool(buffer);
}

/**
 * \brief Modify information in the table of given header
 * \param header Table header (only 0-3 implemented)
 * \return
 */
NTSTATUS Smbios::ProcessTable(SMBIOS_HEADER* header)
{
    if (!header->Length) {
        DbgPrintEx(0, 0, "skipping header->Type = %d; empty length\n", header->Type);
        return STATUS_UNSUCCESSFUL;
    }
    if (header->Type == 0)
    {
        DbgPrintEx(0, 0, "patching header->Type = %d\n", header->Type);
        auto* type0 = reinterpret_cast<SMBIOS_TYPE0*>(header);
        auto* vendor = GetString(header, type0->Vendor);
        DbgPrintEx(0, 0, "header->Type = %d vendor = %s\n", header->Type, vendor);
    } else if (header->Type == 1)
    {
        DbgPrintEx(0, 0, "patching header->Type = %d\n", header->Type);
        auto* type1 = reinterpret_cast<SMBIOS_TYPE1*>(header);
        auto* manufacturer = GetString(header, type1->Manufacturer);
        auto* productName = GetString(header, type1->ProductName);
        auto* serialNumber = GetString(header, type1->SerialNumber);
        DbgPrintEx(0, 0, "header->Type = %d manufacturer = %s productName = %s serialNumber = %s\n", header->Type, manufacturer, productName, serialNumber);
    } else if (header->Type == 2)
    {
        DbgPrintEx(0, 0, "patching header->Type = %d\n", header->Type);
        auto* type2 = reinterpret_cast<SMBIOS_TYPE2*>(header);
        auto* manufacturer = GetString(header, type2->Manufacturer);
        auto* productName = GetString(header, type2->ProductName);
        auto* serialNumber = GetString(header, type2->SerialNumber);
        //productName[0] = 'L';
        DbgPrintEx(0, 0, "header->Type = %d manufacturer = %s productName = %s serialNumber = %s\n", header->Type, manufacturer, productName, serialNumber);
        DbgPrintEx(0, 0, "header->Type = %d productName = %p type2->ProductName = %p\n", header->Type, productName, type2->ProductName);
    } else if (header->Type == 3)
    {
        DbgPrintEx(0, 0, "patching header->Type = %d\n", header->Type);
        auto* type3 = reinterpret_cast<SMBIOS_TYPE3*>(header);
        auto* manufacturer = GetString(header, type3->Manufacturer);
        auto* serialNumber = GetString(header, type3->SerialNumber);
        DbgPrintEx(0, 0, "header->Type = %d manufacturer = %s serialNumber = %s\n", header->Type, manufacturer, serialNumber);
    }
    else {
        DbgPrintEx(0, 0, "skipping header->Type = %d\n", header->Type);
    }

    return STATUS_SUCCESS;
}

/// BIOS Information (Type 0)
/// System Information (Type 1)
/// Baseboard (or Module) Information (Type 2)
/// System Enclosure or Chassis (Type 3)
/// Processor Information (Type 4)
/// Memory Controller Information (Type 5, Obsolete)
/// Memory Module Information (Type 6, Obsolete)
/// Cache Informaiton (Type 7)
/// Port Connector Information (Type 8)
/// System Slot Information (Type 9)
/// On Board Devices Information (Type 10, Obsolete)
/// OEM Strings (Type 11)
/// System Configuration Options (Type 12)
/// BIOS Language Information (Type 13)
/// Group Associations (Type 14)
/// System Event Log (Type 15)
/// Physical Memory Array (Type 16)
/// Memory Device (Type 17)
/// 32-Bit Memory Error Information (Type 18)
/// Memory Array Mapped Address (Type 19)
/// Memory Device Mapped Address (Type 20)
/// Built-in Pointing Device (Type 21)
/// Portable Battery (Type 22)
/// System Reset (Type 23)
/// Hardware Security (Type 24)
/// System Power Controls (Type 25)
/// Voltage Probe (Type 26)
/// Cooling Device (Type 27)
/// Temperature Probe (Type 28)
/// Electrical Current Probe (Type 29)
/// Out-of-Band Remote Access (Type 30)
/// Boot Integrity Services (BIS) (Type 31)
/// System Boot Information (Type 32)
/// 64-Bit Memory Error Information (Type 33)
/// Management Device (Type 34)
/// Management Device Component (Type 35)
/// Management Device Threshold Data (Type 36)
/// Memory Channel (Type 37)
/// IPMI Device Information (Type 38)
/// Power Supply (Type 39)
/// Additional Information (Type 40)
/// Onboard Devices Extended Information (Type 41)
/// Management Controller Host Interface (Type 42)
/// TPM Device (Type 43)
/// Processor Additional Information (Type 44)
/// Firmware Inventory Information (Type 45)
/// String Property (Type 46)
/// Inactive (Type 126)
/// End-of-Table (Type 127)

/**
 * \brief Loop through SMBIOS tables with provided first table header
 * \param mapped Header of the first table
 * \param size Size of all tables including strings
 * \return
 */
NTSTATUS Smbios::LoopTables(void* mapped, ULONG size)
{
    auto* endAddress = static_cast<char*>(mapped) + size;
    while (true)
    {
        auto* header = static_cast<SMBIOS_HEADER*>(mapped);
        DbgPrintEx(0, 0, "LoopTables header->Type = %d header->Length = %d\n", header->Type, header->Length);
        if (header->Type == 127 && header->Length == 4)
            break;

        ProcessTable(header);

        auto* end = static_cast<char*>(mapped) + header->Length;
        while (0 != (*end | *(end + 1))) end++;
        end += 2;
        if (end >= endAddress)
            break;

        mapped = end;
    }

    return STATUS_SUCCESS;
}

/**
 * \brief Find SMBIOS physical address, map it and then loop through
 * table 0-3 and modify possible identifiable information
 * \return Status of the change (will return STATUS_SUCCESS if mapping was successful)
 */
NTSTATUS Smbios::ChangeSmbiosSerials()
{
    auto* base = Utils::GetModuleBase("ntoskrnl.exe");
    if (!base)
    {
        DbgPrintEx(0, 0, "Failed to find ntoskrnl.sys base!\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "base = %p\n", base);

    auto* physicalAddress = static_cast<PPHYSICAL_ADDRESS>(Utils::FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx")); // WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
    if (!physicalAddress)
    {
        DbgPrintEx(0, 0, "Failed to find SMBIOS physical address!\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "physicalAddress = %p\n", physicalAddress);

    physicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physicalAddress) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physicalAddress) + 3));
    if (!physicalAddress)
    {
        DbgPrintEx(0, 0, "Physical address is null!\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "physicalAddress = %p\n", physicalAddress);

    auto* sizeScan = Utils::FindPatternImage(base, "\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B", "xx????xxxxxxxxxx????xxxx");  // WmipFindSMBiosStructure -> WmipSMBiosTableLength
    if (!sizeScan)
    {
        DbgPrintEx(0, 0, "Failed to find SMBIOS size!\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "sizeScan = %p\n", sizeScan);

    const auto size = *reinterpret_cast<ULONG*>(static_cast<char*>(sizeScan) + 6 + *reinterpret_cast<int*>(static_cast<char*>(sizeScan) + 2));
    if (!size)
    {
        DbgPrintEx(0, 0, "SMBIOS size is null!\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "size = %d\n", size);

    auto* mapped = MmMapIoSpace(*physicalAddress, size, MmNonCached);
    if (!mapped)
    {
        DbgPrintEx(0, 0, "Failed to map SMBIOS structures!\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "mapped = %p\n", mapped);

    LoopTables(mapped, size);

    MmUnmapIoSpace(mapped, size);

    return STATUS_SUCCESS;
}