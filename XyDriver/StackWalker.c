#include "StackWalker.h"

#define	NF_TAG_STACK 'SgTg'

#define MEM_IMAGE 0x1000000
#define MemoryMappedFilenameInformation 0x2

//堆栈追溯
VOID WalkAndResolveStack(_Inout_ PSTACK_RETURN_INFO* ResolvedStack,_Inout_ PULONG ResolvedStackSize,_In_ ULONG ResolvedStackTag)
{
	PVOID* stackReturnPtrs;
	ULONG capturedReturnPtrs;
	ULONG i;

	capturedReturnPtrs = 0;
	*ResolvedStack = NULL;

	stackReturnPtrs = (PVOID*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID) * *ResolvedStackSize, NF_TAG_STACK);
	if (stackReturnPtrs == NULL)
	{
		goto FINAL;
	}

	RtlZeroMemory(stackReturnPtrs, sizeof(PVOID) * *ResolvedStackSize);

	capturedReturnPtrs = RtlWalkFrameChain(stackReturnPtrs, *ResolvedStackSize, 1);
	if (capturedReturnPtrs == 0)
	{
		goto FINAL;
	}

	//NT_ASSERT(capturedReturnPtrs < ResolvedStackSize);

	*ResolvedStackSize = capturedReturnPtrs;

	*ResolvedStack = (PSTACK_RETURN_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(STACK_RETURN_INFO) * *ResolvedStackSize, ResolvedStackTag);
	if (*ResolvedStack == NULL)
	{
		goto FINAL;
	}
	RtlZeroMemory(*ResolvedStack,sizeof(STACK_RETURN_INFO) * *ResolvedStackSize);

	for (i = 0; i < capturedReturnPtrs; i++)
	{
		(*ResolvedStack)[i].RawAddress = stackReturnPtrs[i];

		//地址大于等于MmUserProbeAddress，则说明指针在用户空间范围，否则指针则在内核空间内
		if ((ULONG64)(stackReturnPtrs[i]) < MmUserProbeAddress && IsAddressExecutable(stackReturnPtrs[i]))
		{
			(*ResolvedStack)[i].ExecutableMemory = TRUE;
			ResolveAddressModule(stackReturnPtrs[i], &(*ResolvedStack)[i]);
		}
	}

FINAL:
	if (stackReturnPtrs)
	{
		ExFreePoolWithTag(stackReturnPtrs, NF_TAG_STACK);
		stackReturnPtrs = NULL;
	}
}

//判断内存地址是不是可执行
BOOL IsAddressExecutable(_In_ PVOID Address)
{
	NTSTATUS status;
	MEMORY_BASIC_INFORMATION memoryBasicInformation;
	BOOLEAN executable = FALSE;

	RtlZeroMemory(&memoryBasicInformation,sizeof(memoryBasicInformation));

	status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, MemoryBasicInformation, &memoryBasicInformation, sizeof(memoryBasicInformation), NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		goto FINAL;
	}

	executable = FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE) ||
		FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_READ) ||
		FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_READWRITE) ||
		FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_WRITECOPY);
FINAL:
	return NT_SUCCESS(status) && executable;
}

//获取内存相关信息
VOID ResolveAddressModule(_In_ PVOID Address,_Inout_ PSTACK_RETURN_INFO StackReturnInfo)
{
	NTSTATUS status;
	MEMORY_BASIC_INFORMATION meminfo;
	SIZE_T returnLength;
	SIZE_T mappedFilenameLength;
	PUNICODE_STRING mappedFilename = NULL;

	mappedFilenameLength = sizeof(UNICODE_STRING) + MAX_PATH * 2;

	status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, MemoryBasicInformation, &meminfo, sizeof(meminfo), &returnLength);
	if (NT_SUCCESS(status) && meminfo.Type == MEM_IMAGE)
	{
		StackReturnInfo->MemoryInModule = TRUE;
		StackReturnInfo->BinaryOffset = (ULONG64)Address - (ULONG64)meminfo.AllocationBase;

		mappedFilename = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, mappedFilenameLength, NF_TAG_STACK);
		if (mappedFilename == NULL)
		{
			goto FINAL;
		}

		status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, (MEMORY_INFORMATION_CLASS)MemoryMappedFilenameInformation, mappedFilename, mappedFilenameLength, &mappedFilenameLength);
		if (status == STATUS_BUFFER_OVERFLOW)
		{
			ExFreePoolWithTag(mappedFilename, NF_TAG_STACK);
			mappedFilename = NULL;
			mappedFilename = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, mappedFilenameLength, NF_TAG_STACK);
			if (mappedFilename == NULL)
			{
				goto FINAL;
			}
			status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, (MEMORY_INFORMATION_CLASS)MemoryMappedFilenameInformation, mappedFilename, mappedFilenameLength, &mappedFilenameLength);
		}

		if (!NT_SUCCESS(status))
		{
			goto FINAL;
		}

		RtlCopyMemory(StackReturnInfo->BinaryPath, mappedFilename->Buffer, sizeof(StackReturnInfo->BinaryPath));
	}

FINAL:
	if (mappedFilename)
	{
		ExFreePoolWithTag(mappedFilename, NF_TAG_STACK);
		mappedFilename = NULL;
	}
}
