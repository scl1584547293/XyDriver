#include "process.h"
#include "devctrl.h"
#include "MonitorHandle.h"
#include "policy.h"
#include "StackWalker.h"


//TODO 阻止进程创建可以使用 PsSetCreateProcessNotifyRoutineEx 函数

#define NF_TAG_PROCESS 'PgTg'
#define NF_TAG_PROCESS_BUF 'PbTg'

//一条数据申请内存大小
#define PROCESS_ALLOCATESIZE sizeof(MonitorMsg)+sizeof(PROCESSINFO)
#define PROCESS_DATAMAXNUM LIST_MAX_SIZE/PROCESS_ALLOCATESIZE


//进程模块是否初始化
static BOOL g_IsProcessInit = FALSE;

//申请内存的List
static NPAGED_LOOKASIDE_LIST g_processList;
//进程数据
static DEVDATA g_processData;

static BOOL g_IsClean = FALSE;

//回调函数 xp下不支持
static VOID Process_NotifyProcessEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	PMonitorMsg pProcessMsg = NULL;

	if (CreateInfo && !GetTypeConfig(MT_ProcessCreate))
		goto FINAL;

	if (!CreateInfo && !GetTypeConfig(MT_ProcessExit))
		goto FINAL;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL || ProcessId ==0 || ProcessId == PsGetProcessId(PsInitialSystemProcess))
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(PROCESSINFO);

	//莫名其妙的崩溃（必须申请内存，直接定义变量会崩溃）
	pProcessMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, PROCESS_ALLOCATESIZE, NF_TAG_PROCESS);
	if (pProcessMsg == NULL)
	{
		KdPrint(("%s:%d(%s) [Process]ExAllocatePoolWithTag PROCESSINFO err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pProcessMsg, PROCESS_ALLOCATESIZE);

	PPROCESSINFO pProcessInfo = (PPROCESSINFO)pProcessMsg->data;
	if (!pProcessInfo)
		goto FINAL;

	pProcessMsg->common.type = Monitor_Process;
	pProcessMsg->common.pid = (DWORD)ProcessId;

	pProcessInfo->threadId = (DWORD)PsGetCurrentThreadId();
	GetCurrentTimeString(&pProcessMsg->common.time);
	
	//QueryProcessCreateTime((DWORD)ProcessId,&pProcessInfo->createTime);

	//根据进程id获取进程名
	GetProcessNameByPID((DWORD)ProcessId, pProcessMsg->common.comm, sizeof(pProcessMsg->common.comm),&pProcessMsg->common.ppid);

	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)ProcessId, &pProcessInfo->createTime);

	WCHARMAX processPath = { 0 };
	if (QueryProcessNamePath((DWORD)ProcessId, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pProcessMsg->common.exe, processPath, sizeof(WCHARMAX));
		if (!IsAllowData(POLICY_EXE_LIST, pProcessMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else 
	{
		if (!IsAllowData(POLICY_EXE_LIST, pProcessMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	//创建进程
	if (CreateInfo)
	{
		pProcessInfo->processType = MT_ProcessCreate;
		pProcessMsg->common.ppid = (DWORD)CreateInfo->ParentProcessId;

		pProcessInfo->pThreadId = (DWORD)CreateInfo->CreatingThreadId.UniqueThread;

		if (CreateInfo->CommandLine && (CreateInfo->CommandLine->Length < sizeof(WCHARMAX)))
			RtlCopyMemory(pProcessInfo->commandLine, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);

		//if (CreateInfo->FileOpenNameAvailable)
		//{
		//	if (CreateInfo->ImageFileName->Length < sizeof(WCHARMAX))
		//		RtlCopyMemory(pProcessInfo->parenPath, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
		//}
		//else
		//{
		//	WCHAR processPath[MAX_PATH] = { 0 };
		//	if (!QueryProcessNamePath((DWORD)ProcessId, processPath, sizeof(processPath)))
		//	{
		//		KdPrint(("%s:%d(%s) [Process]QueryProcessNamePath err\n", __FILE__, __LINE__, __FUNCTION__));
		//		goto FINAL;
		//	}

		//	RtlCopyMemory(pProcessInfo->parenPath, processPath, MAX_PATH * sizeof(WCHAR));
		//}

		//父进程的id
		//pProcessInfo->threadId = (DWORD)CreateInfo->CreatingThreadId.UniqueThread;
		//pProcessInfo->pid = (DWORD)CreateInfo->CreatingThreadId.UniqueProcess;
		
		//堆栈回溯
		//PSTACK_RETURN_INFO CallerStackHistory;
		//ULONG ResolvedStackSize = 30;
		//WalkAndResolveStack(&CallerStackHistory, &ResolvedStackSize, NF_TAG_PROCESS);

		//for (DWORD i = 0; i < ResolvedStackSize; i++)
		//{
		//	if (CallerStackHistory[i].MemoryInModule == FALSE &&
		//		CallerStackHistory[i].ExecutableMemory &&
		//		CallerStackHistory[i].RawAddress != 0x0 &&
		//		(ULONG64)CallerStackHistory[i].RawAddress < MmUserProbeAddress)
		//	{
		//		KdPrint(("====0x%p,%d,%d,%S+%p\n", CallerStackHistory[i].RawAddress, CallerStackHistory[i].MemoryInModule, 
		//			CallerStackHistory[i].ExecutableMemory,
		//			CallerStackHistory[i].BinaryPath, CallerStackHistory[i].BinaryOffset));
		//	}
		//}

		//if (CallerStackHistory)
		//{
		//	ExFreePoolWithTag(CallerStackHistory, NF_TAG_PROCESS);
		//	CallerStackHistory = NULL;
		//}


	}
	//销毁进程
	else
	{
		pProcessInfo->processType = MT_ProcessExit;
	}

	//父进程路径
	WCHARMAX parentPath = { 0 };
	if (QueryProcessNamePath((DWORD)pProcessMsg->common.ppid, parentPath, sizeof(parentPath)))
	{
		RtlCopyMemory(pProcessInfo->parenPath, parentPath, sizeof(WCHARMAX));
	}
	
	PDEVBUFFER pInfo = (PDEVBUFFER)ProcessPacketAllocate(PROCESS_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [Process]ProcessPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pProcessMsg, PROCESS_ALLOCATESIZE);

	//检测数据量
	CheckProcessDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_processData.lock, &lh);
	InsertHeadList(&g_processData.pending, &pInfo->pEntry);

	g_processData.dataSize++;
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s) %d[Process]%d-%d:path%S,cmd:%S,name%s,parenPath:%S\n", __FILE__,__LINE__, __FUNCTION__, 
		pProcessInfo->processType, pProcessMsg->common.ppid, pProcessMsg->common.pid, pProcessMsg->common.exe,
		pProcessInfo->commandLine, pProcessMsg->common.comm, pProcessInfo->parenPath));

	//添加采集数据
	PushInfo(Monitor_Process);

FINAL:
	if (pProcessMsg)
	{
		ExFreePoolWithTag(pProcessMsg, NF_TAG_PROCESS);
		pProcessMsg = NULL;
	}
	return;
}

static VOID Process_NotifyProcess(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create)
{
	PMonitorMsg pProcessMsg = NULL;

	if (Create && !GetTypeConfig(MT_ProcessCreate))
		goto FINAL;

	if (!Create && !GetTypeConfig(MT_ProcessExit))
		goto FINAL;

	if (KeGetCurrentIrql() > APC_LEVEL || ProcessId == 0 || ProcessId == PsGetProcessId(PsInitialSystemProcess))
		goto FINAL;


	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(PROCESSINFO);

	//莫名其妙的崩溃（必须申请内存，直接定义变量会崩溃）
	pProcessMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, PROCESS_ALLOCATESIZE, NF_TAG_PROCESS);
	if (pProcessMsg == NULL)
	{
		KdPrint(("%s:%d(%s) [Process]ExAllocatePoolWithTag PROCESSINFO err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pProcessMsg, PROCESS_ALLOCATESIZE);

	PPROCESSINFO pProcessInfo = (PPROCESSINFO)pProcessMsg->data;
	if (!pProcessInfo)
		goto FINAL;

	pProcessMsg->common.type = Monitor_Process;
	pProcessMsg->common.pid = (DWORD)ProcessId;

	pProcessInfo->threadId = (DWORD)PsGetCurrentThreadId();
	GetCurrentTimeString(&pProcessMsg->common.time);
	//QueryProcessCreateTime((DWORD)ProcessId,&pProcessInfo->createTime);

	//根据进程id获取进程名
	GetProcessNameByPID((DWORD)ProcessId, pProcessMsg->common.comm, sizeof(pProcessMsg->common.comm),&pProcessMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)ProcessId, &pProcessInfo->createTime);

	WCHARMAX processPath = { 0 };
	if (QueryProcessNamePath((DWORD)ProcessId, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pProcessMsg->common.exe, processPath, sizeof(WCHARMAX));
		if (!IsAllowData(POLICY_EXE_LIST, pProcessMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pProcessMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	if(Create)
		pProcessInfo->processType = MT_ProcessCreate;
	else
		pProcessInfo->processType = MT_ProcessExit;
	pProcessMsg->common.ppid = (DWORD)ParentId;

	PDEVBUFFER pInfo = (PDEVBUFFER)ProcessPacketAllocate(PROCESS_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [Process]ProcessPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pProcessMsg, PROCESS_ALLOCATESIZE);

	//检测数据量
	CheckProcessDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_processData.lock, &lh);
	InsertHeadList(&g_processData.pending, &pInfo->pEntry);

	g_processData.dataSize++;
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s) %d[Process]%d-%d:path%S,cmd:%S,name%s,parenPath:%S\n", __FILE__, __LINE__, __FUNCTION__,
		pProcessInfo->processType, pProcessMsg->common.ppid, pProcessMsg->common.pid, pProcessMsg->common.exe,
		pProcessInfo->commandLine, pProcessMsg->common.comm, pProcessInfo->parenPath));

	//添加采集数据
	PushInfo(Monitor_Process);

FINAL:
	if (pProcessMsg)
	{
		ExFreePoolWithTag(pProcessMsg, NF_TAG_PROCESS);
		pProcessMsg = NULL;
	}
	return;
}
//static PVOID g_ProcessRegistrationHandle = NULL;
//static OB_OPERATION_REGISTRATION obOperationRegistrations;

//进程模块初始化
NTSTATUS ProcessInit()
{
	NTSTATUS status = STATUS_SUCCESS;

	sl_init(&g_processData.lock);
	InitializeListHead(&g_processData.pending);

	ExInitializeNPagedLookasideList(
		&g_processList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;

#ifndef WINXP
	//添加进程回调
	status = PsSetCreateProcessNotifyRoutineEx(Process_NotifyProcessEx, FALSE);
#else
	status = PsSetCreateProcessNotifyRoutine(Process_NotifyProcess, FALSE);
#endif	
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [Process]Process_NotifyProcess err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		return status;
	}

	g_IsProcessInit = TRUE;

	return status;
}

//TODO 记录进程、线程句柄打开
//OB_OPERATION_REGISTRATION obOperationRegistrations[1];
//PVOID pRegistrationHandle = NULL;
//
////回调函数
//POB_PRE_OPERATION_CALLBACK PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
//{
//	UNREFERENCED_PARAMETER(RegistrationContext);
//
//	//获取进程信息
//	PEPROCESS process = (PEPROCESS)PreInfo->Object;
//
//	//进程
//	if (PreInfo->ObjectType == *PsProcessType)
//	{
//		process = IoThreadToProcess((PETHREAD)PreInfo->Object);
//	}
//	//线程
//	else if (PreInfo->ObjectType == *PsThreadType)
//	{
//		process = (PEPROCESS)PreInfo->Object;
//	}
//	else
//	{
//		return OB_PREOP_SUCCESS;
//	}
//
//	//获取对应进程/线程信息
//	if (PreInfo->ObjectType == *PsThreadType) {
//		process = IoThreadToProcess((PETHREAD)PreInfo->Object);
//	}
//	if (PreInfo->ObjectType == *PsProcessType) {
//		process = (PEPROCESS)PreInfo->Object;
//	}
//	//获取进程名
//	PUCHAR processName = PsGetProcessImageFileName(process);
//
//	//过滤的进程名
//	if (_stricmp((char *)processName, "notepad++.exe") != 0) {
//		return OB_PREOP_SUCCESS;
//	}
//
//	//修改权限不让退出
//	if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
//		PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
//	}
//	if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
//		PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
//	}
//	return OB_PREOP_SUCCESS;
//}
//
//
//ObUnRegisterCallbacks(pRegistrationHandle);


//清理进程模块
VOID CleanProcess()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_processData.lock, &lh);
		lock_status = 1;

		while (!IsListEmpty(&g_processData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_processData.pending);
			if (!pData)
				break;

			g_processData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			ProcessPacketFree(pData);
			pData = NULL;
			sl_lock(&g_processData.lock, &lh);
			lock_status = 1;
		}

		sl_unlock(&lh);
		lock_status = 0;
	}
	finally {
		if (1 == lock_status)
			sl_unlock(&lh);
	}
}

//释放进程模块
VOID FreeProcess()
{
	if (!g_IsClean)
		return;

	CleanProcess();
	ExDeleteNPagedLookasideList(&g_processList);

	if (g_IsProcessInit)
	{
#ifndef WINXP
		PsSetCreateProcessNotifyRoutineEx(Process_NotifyProcessEx, TRUE);
#else
		PsSetCreateProcessNotifyRoutine(Process_NotifyProcess, TRUE);
#endif

		g_IsProcessInit = FALSE;
	}

	return;
}

//从List中申请内存
PDEVBUFFER ProcessPacketAllocate(int lens)
{
	PDEVBUFFER pProcessbuf = NULL;
	if (lens <= 0)
		return pProcessbuf;

	pProcessbuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_processList);
	if (!pProcessbuf)
		return pProcessbuf;

	RtlZeroMemory(pProcessbuf, sizeof(DEVBUFFER));

	pProcessbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_PROCESS_BUF);
	if (!pProcessbuf->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_processList, pProcessbuf);
		pProcessbuf = NULL;
		return pProcessbuf;
	}
	pProcessbuf->dataLength = lens;
	RtlZeroMemory(pProcessbuf->dataBuffer,lens);
	
	return pProcessbuf;
}

//释放内存
void ProcessPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;

	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_PROCESS_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_processList, packet);
}

//获取存储数据信息
PDEVDATA GetProcessCtx()
{
	return &g_processData;
}

//检测数据量
VOID CheckProcessDataNum()
{
	if (g_processData.dataSize > PROCESS_DATAMAXNUM)
	{
		CleanProcess();

		//KLOCK_QUEUE_HANDLE lh;
		//sl_lock(&g_processData.lock, &lh);
		//g_processData.dataSize = 0;
		//sl_unlock(&lh);
	}
}

//=============================================================================//
//句柄监控回调函数
OB_PREOP_CALLBACK_STATUS PreProcessCallback(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(PreInfo);

	PMonitorMsg pProcessMsg = NULL;

	if (!g_IsProcessInit || !GetTypeConfig(Monitor_Process) || NULL == PreInfo->Object || PreInfo->ObjectType != *PsProcessType || KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		goto FINAL;
	}

	//获取进程信息
	PEPROCESS pEProcess = (PEPROCESS)PreInfo->Object;
	if (NULL == pEProcess)
		goto FINAL;

	//进程id
	HANDLE pid = PsGetProcessId(pEProcess);
	if (pid == 0 || pid == PsGetProcessId(PsInitialSystemProcess))
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(PROCESSINFO);

	//莫名其妙的崩溃（必须申请内存，直接定义变量会崩溃）
	pProcessMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, PROCESS_ALLOCATESIZE, NF_TAG_PROCESS);
	if (pProcessMsg == NULL)
	{
		KdPrint(("%s:%d(%s) [Process]ExAllocatePoolWithTag PROCESSINFO err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pProcessMsg, PROCESS_ALLOCATESIZE);

	PPROCESSINFO pProcessInfo = (PPROCESSINFO)pProcessMsg->data;
	if (!pProcessInfo)
		goto FINAL;

	pProcessMsg->common.type = Monitor_Process;
	pProcessMsg->common.pid = (DWORD)pid;
	pProcessInfo->threadId = (DWORD)PsGetCurrentThreadId();

	pProcessMsg->common.ppid = (DWORD)PsGetProcessInheritedFromUniqueProcessId(pEProcess);
	GetCurrentTimeString(&pProcessMsg->common.time);

	//获取进程名
	PUCHAR processName = PsGetProcessImageFileName(pEProcess);
	if (processName != NULL)
		RtlCopyMemory(pProcessMsg->common.comm, processName, 32);


	//根据进程id获取进程创建时间
	LONGLONG timeQuadPart = PsGetProcessCreateTimeQuadPart(pEProcess);
	if (timeQuadPart != 0)
	{
		//转成unix时间戳，11644473600是1601到1901的秒数
		pProcessInfo->createTime = timeQuadPart / 10000000 - 11644473600;

		//LARGE_INTEGER current_local_time;
		////从系统时间转换成当地时区时间
		//ExSystemTimeToLocalTime(&timeQuadPart, &current_local_time);
		//RtlTimeToTimeFields(&current_local_time, &pProcessInfo->createTime);
	}


	//不知道为啥，ZwOpenProcess时会蓝屏
	//WCHARMAX processPath = { 0 };
	//if (QueryProcessNamePath((DWORD)pid, processPath, sizeof(processPath)))
	//{
	//	RtlCopyMemory(pProcessMsg->common.exe, processPath, sizeof(WCHARMAX));
	//	if (!IsAllowData(POLICY_EXE_LIST, pProcessMsg->common.exe, TRUE))
	//	{
	//		goto FINAL;
	//	}
	//}
	//else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pProcessMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	ACCESS_MASK accessMask = 0;
	if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		accessMask = PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;	
	}
	else if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		accessMask = PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
	}
	else
	{
		goto FINAL;
	}

	//暂停恢复
	//PROCESS_SUSPEND_RESUME 0x0800
	if (accessMask & 0x0800)
	{
		pProcessInfo->processType = MT_ProcessStart;
		if (!GetTypeConfig(MT_ProcessStart))
			goto FINAL;

		KdPrint(("%s:%d(%s) [启动进程]pid:%d,threadid:%d,name:%s\n", __FILE__, __LINE__, __FUNCTION__,
			pProcessMsg->common.pid, pProcessInfo->threadId, pProcessMsg->common.comm));
	}
	else
	{
		pProcessInfo->processType = MT_ProcessOpen;

		if (!GetTypeConfig(MT_ProcessOpen))
			goto FINAL;

		KdPrint(("%s:%d(%s) [打开进程]pid:%d,threadid:%d,name:%s\n", __FILE__, __LINE__, __FUNCTION__,
			pProcessMsg->common.pid, pProcessInfo->threadId, pProcessMsg->common.comm));
	}	

	PDEVBUFFER pInfo = (PDEVBUFFER)ProcessPacketAllocate(PROCESS_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [Process]ProcessPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pProcessMsg, PROCESS_ALLOCATESIZE);

	//检测数据量
	CheckProcessDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_processData.lock, &lh);
	InsertHeadList(&g_processData.pending, &pInfo->pEntry);

	g_processData.dataSize++;
	sl_unlock(&lh);

	//添加采集数据
	PushInfo(Monitor_Process);

FINAL:
	if (pProcessMsg)
	{
		ExFreePoolWithTag(pProcessMsg, NF_TAG_PROCESS);
		pProcessMsg = NULL;
	}
	return OB_PREOP_SUCCESS;
}
