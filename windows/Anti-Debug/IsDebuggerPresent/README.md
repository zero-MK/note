```c
	if (IsDebuggerPresent() != 0) {
		MessageBoxA(0, "debug", "debug", 0);
	}
```

对应的汇编代码

```asm
75A94E10  mov         eax,dword ptr fs:[00000030h]  
75A94E16  movzx       eax,byte ptr [eax+2]  
75A94E1A  ret 
```

![image-20201207233403054](https://gitee.com/scriptkiddies/images/raw/master/image-20201207233403054.png)

其实原理很简单

```asm
mov         eax,dword ptr fs:[00000030h] 
```

这一句获取进程的 PEB，在 x86 的环境下 fs 寄存器存的是 TEB 结构的指针，在 TEB 中偏移量为 0x30 的地方存有进程的 PEB

PEB 的结构

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

 PEB 中偏移量对应的字段是 BeingDebugged ，这个字段标志这进程是否正在被调试

如果正在调试进程，则为 1，否则为 0