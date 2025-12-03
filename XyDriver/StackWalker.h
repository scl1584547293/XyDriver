#pragma once
#include "public.h"

typedef struct StackReturnInfo
{
	//内存地址
	PVOID RawAddress;
	//地址是否在已加载的模块中
	BOOLEAN MemoryInModule;	
	//内存地址属性是否时可执行
	BOOLEAN ExecutableMemory;
	//地址所属模块路径
	WCHAR BinaryPath[MAX_PATH];
	//地址相对于模块的偏移量
	ULONG64 BinaryOffset;
} STACK_RETURN_INFO, *PSTACK_RETURN_INFO;

//堆栈追溯
VOID WalkAndResolveStack(_Inout_ PSTACK_RETURN_INFO* ResolvedStack,_Inout_ PULONG ResolvedStackSize,_In_ ULONG ResolvedStackTag);

//判断内存地址是不是可执行
BOOL IsAddressExecutable(_In_ PVOID Address);
//获取内存相关信息
VOID ResolveAddressModule(_In_ PVOID Address,_Inout_ PSTACK_RETURN_INFO StackReturnInfo);