## Vuln_Driver_BlindEDR

一个概念验证。如果只有ZwMapViewOfSection或者MMmapIOSpace的易受攻击驱动能否致盲AV/EDR

### 原理

通过易受攻击的驱动(WinIO64.sys) 来映射物理内存 因为ntoskrnl 一般都是在开机前启动的 都在低地址

所以我们只需要在低物理地址寻找'MZ' magic 头 就可以找到我们的ntoskrnl 

通过给ntoskrnl的冷门函数(可被ring3 syscall并且很少人使用的函数)写inline jump 到我们需要的函数

比如MmAllocateContiguousMemory  GetPhysicalMemoryAddress ObUnRegisterCallbacks CmunRegisterCallback 来通过API清除回调而不通过摘链来清除回调 降低蓝屏概率

### 成果

目前运行后清除了两个回调 CmRegisterCallback ObRegisterCallbacks

现在AV/EDR的进程已经不受其驱动的保护 当我们结束进程的时候驱动不会降权我们的操作 

于是我们可以成功终结AV/EDR进程

### 问题

目前不会短时间蓝屏 在几小时后会触发PatchGuard 