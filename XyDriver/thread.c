#include "thread.h"
#include "process.h"
#include "devctrl.h"
#include "policy.h"

#define NF_TAG_THREAD 'TgTg'
#define NF_TAG_THREAD_BUF 'TbTg'

//一条数据申请内存大小
#define THREAD_ALLOCATESIZE sizeof(MonitorMsg) + sizeof(THREADINFO)
#define THREAD_DATAMAXNUM LIST_MAX_SIZE/THREAD_ALLOCATESIZE

//线程模块是否初始化
static BOOL g_IsThreadInit = FALSE;

//申请内存的List
static NPAGED_LOOKASIDE_LIST g_threadList;
//线程数据
static DEVDATA g_threadData;

static BOOL g_IsClean = FALSE;

//初始化线程模块
NTSTATUS ThreadInit()
{
	NTSTATUS status = STATUS_SUCCESS;

	sl_init(&g_threadData.lock);
	InitializeListHead(&g_threadData.pending);

	ExInitializeNPagedLookasideList(
		&g_threadList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;

	//初始化线程回调
	status = PsSetCreateThreadNotifyRoutine(ThreadNotifyProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [Thread]PsSetCreateThreadNotifyRoutine err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		return status;
	}

	g_IsThreadInit = TRUE;
	return status;
}

//清理线程模块
VOID CleanThread()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_threadData.lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_threadData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_threadData.pending);
			if (!pData)
				break;
			g_threadData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			ThreadPacketFree(pData);
			pData = NULL;
			sl_lock(&g_threadData.lock, &lh);
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

//释放线程模块
VOID FreeThread()
{
	if (!g_IsClean)
		return;

	CleanThread();
	ExDeleteNPagedLookasideList(&g_threadList);

	if(g_IsThreadInit)
	{
		PsRemoveCreateThreadNotifyRoutine(ThreadNotifyProcess);
		g_IsThreadInit = FALSE;
	}
		
	return;
}

//线程回调函数
VOID ThreadNotifyProcess(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
	PMonitorMsg pThreadMsg = NULL;

	if (Create && !GetTypeConfig(MT_ThreadCreate))
		goto FINAL;
	if (!Create && !GetTypeConfig(MT_ThreadExit))
		goto FINAL;

	if (ProcessId == 0 || ProcessId == PsGetProcessId(PsInitialSystemProcess))
		goto FINAL;

	//if (!IsAllowProcess(processPath))
	//	goto FINAL;

	//if (!GetNTLinkName(processPath, linkProcessPath))
	//{
	//	KdPrint(("%s:%d [Thread]GetNTLinkName err\n", __FILE__, __LINE__));
	//	return;
	//}
	//RtlStringCbCopyNW(linkProcessPath, MAX_PATH, processPath, MAX_PATH);

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(THREADINFO);

	//莫名其妙的崩溃（必须申请内存，直接定义变量会崩溃）
	pThreadMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, THREAD_ALLOCATESIZE, NF_TAG_THREAD);
	if (pThreadMsg == NULL)
	{
		KdPrint(("%s:%d(%s) [Thread]ExAllocatePoolWithTag THREADINFO err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pThreadMsg, THREAD_ALLOCATESIZE);

	PTHREADINFO pThreadInfo = (PTHREADINFO)pThreadMsg->data;
	if (!pThreadInfo)
		goto FINAL;

	pThreadMsg->common.type = Monitor_Thread;

	pThreadInfo->threadType = Create? MT_ThreadCreate: MT_ThreadExit;
	pThreadInfo->threadId = (DWORD)ThreadId;
	pThreadMsg->common.pid = (DWORD)ProcessId;

	//根据进程id获取进程名
	GetProcessNameByPID((DWORD)ProcessId, pThreadMsg->common.comm, sizeof(pThreadMsg->common.comm),&pThreadMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)ProcessId, &pThreadInfo->createTime);

	WCHARMAX processPath = { 0 };
	//根据进程id获取进程路径
	if (QueryProcessNamePath((DWORD)ProcessId, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pThreadMsg->common.exe, processPath, sizeof(WCHARMAX));
		if (!IsAllowData(POLICY_EXE_LIST, pThreadMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pThreadMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	GetCurrentTimeString(&pThreadMsg->common.time);
	
	PDEVBUFFER pInfo = (PDEVBUFFER)ThreadPacketAllocate(THREAD_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [Thread]ThreadPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pThreadMsg, THREAD_ALLOCATESIZE);

	//获取数据量
	CheckThreadDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_threadData.lock, &lh);
	InsertHeadList(&g_threadData.pending, &pInfo->pEntry);

	g_threadData.dataSize++;
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s) [Thread]%d-%d:type:%d,name:%s,processPath:%S\n", __FILE__, __LINE__, __FUNCTION__, 
		pThreadMsg->common.pid, pThreadInfo->threadId, pThreadInfo->threadType, pThreadMsg->common.comm, 
		pThreadMsg->common.exe));

	//添加数据
	PushInfo(Monitor_Thread);

FINAL:
	if (pThreadMsg)
	{
		ExFreePoolWithTag(pThreadMsg, NF_TAG_THREAD);
		pThreadMsg = NULL;
	}
	return;
}


//从List中申请内存
PDEVBUFFER ThreadPacketAllocate(int lens)
{
	PDEVBUFFER pThreadbuf = NULL;
	if (lens <= 0)
		return pThreadbuf;
	pThreadbuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_threadList);
	if (!pThreadbuf)
		return pThreadbuf;

	RtlZeroMemory(pThreadbuf,sizeof(DEVBUFFER));

	pThreadbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_THREAD_BUF);
	if (!pThreadbuf->dataBuffer)
	{
		KdPrint(("%s:%d(%s) [Thread]ExAllocatePoolWithTag err\n", __FILE__, __LINE__, __FUNCTION__));
		ExFreeToNPagedLookasideList(&g_threadList, pThreadbuf);
		pThreadbuf = NULL;
		return pThreadbuf;
	}
	pThreadbuf->dataLength = lens;
	RtlZeroMemory(pThreadbuf->dataBuffer,lens);
	
	return pThreadbuf;
}

//释放内存
void ThreadPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;
	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_THREAD_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_threadList, packet);
}

//获取存储数据信息
PDEVDATA GetThreadCtx()
{
	return &g_threadData;
}

//获取数据量
VOID CheckThreadDataNum()
{
	if (g_threadData.dataSize > THREAD_DATAMAXNUM)
	{
		CleanThread();

		//KLOCK_QUEUE_HANDLE lh;
		//sl_lock(&g_threadData.lock, &lh);
		//g_threadData.dataSize = 0;
		//sl_unlock(&lh);
	}
}


//=============================================================================//
//句柄监控回调函数
OB_PREOP_CALLBACK_STATUS PreThreadCallback(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(PreInfo);

	PMonitorMsg pThreadMsg = NULL;

	if (!g_IsThreadInit || !GetTypeConfig(Monitor_Thread) || NULL == PreInfo->Object || PreInfo->ObjectType != *PsThreadType || KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		goto FINAL;
	}

	//获取进程信息
	PETHREAD pEThread = (PETHREAD)PreInfo->Object;
	PEPROCESS pEProcess = IoThreadToProcess(pEThread);
	if (!pEProcess)
		goto FINAL;

	//进程id
	HANDLE pid = PsGetProcessId(pEProcess);
	HANDLE threadid = PsGetThreadId(pEThread);
	if (pid == 0 || pid == PsGetProcessId(PsInitialSystemProcess))
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(THREADINFO);

	//莫名其妙的崩溃（必须申请内存，直接定义变量会崩溃）
	pThreadMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, THREAD_ALLOCATESIZE, NF_TAG_THREAD);
	if (pThreadMsg == NULL)
	{
		KdPrint(("%s:%d(%s) [Process]ExAllocatePoolWithTag PROCESSINFO err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pThreadMsg, THREAD_ALLOCATESIZE);

	PTHREADINFO pThreadInfo = (PTHREADINFO)pThreadMsg->data;
	if (!pThreadInfo)
	{	
		goto FINAL;
	}
	
	pThreadInfo->threadId = (DWORD)threadid;
	pThreadMsg->common.type = Monitor_Thread;
	pThreadMsg->common.pid = (DWORD)pid;

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

	//获取进程名
	PUCHAR processName = PsGetProcessImageFileName(pEProcess);
	if (processName != NULL)
		RtlCopyMemory(pThreadMsg->common.comm, processName, 32);

	//根据进程id获取进程创建时间
	LONGLONG timeQuadPart = PsGetProcessCreateTimeQuadPart(pEProcess);
	if (timeQuadPart != 0)
	{
		//转成unix时间戳，11644473600是1601到1901的秒数
		pThreadInfo->createTime = timeQuadPart / 10000000 - 11644473600;
		//LARGE_INTEGER current_local_time;
		////从系统时间转换成当地时区时间
		//ExSystemTimeToLocalTime(&timeQuadPart, &current_local_time);
		//RtlTimeToTimeFields(&current_local_time, &pThreadInfo->createTime);
	}

	WCHARMAX processPath = { 0 };
	//根据进程id获取进程路径
	//if (QueryProcessNamePath((DWORD)pid, processPath, sizeof(processPath)))
	//{
	//	RtlCopyMemory(pThreadMsg->common.exe, processPath, sizeof(WCHARMAX));
	//	if (!IsAllowData(POLICY_EXE_LIST, pThreadMsg->common.exe, TRUE))
	//	{
	//		goto FINAL;
	//	}
	//}
	//else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pThreadMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	//暂停恢复
	//PROCESS_SUSPEND_RESUME 0x0800
	if (accessMask & 0x0800)
	{
		pThreadInfo->threadType = MT_ThreadStart;
		if (!GetTypeConfig(MT_ThreadStart))
			goto FINAL;

		KdPrint(("%s:%d(%s) [启动线程]pid:%d,name:%s\n", __FILE__, __LINE__, __FUNCTION__,
			pThreadMsg->common.pid, pThreadMsg->common.comm));
	}
	else
	{
		pThreadInfo->threadType = MT_ThreadOpen;

		if (!GetTypeConfig(MT_ThreadOpen))
			goto FINAL;

		KdPrint(("%s:%d(%s) [打开线程]pid:%d,name:%s\n", __FILE__, __LINE__, __FUNCTION__,
			pThreadMsg->common.pid, pThreadMsg->common.comm));
	}


	GetCurrentTimeString(&pThreadMsg->common.time);

	PDEVBUFFER pInfo = (PDEVBUFFER)ThreadPacketAllocate(THREAD_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [Thread]ThreadPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pThreadMsg, THREAD_ALLOCATESIZE);

	//检测数据量
	CheckThreadDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_threadData.lock, &lh);
	InsertHeadList(&g_threadData.pending, &pInfo->pEntry);

	g_threadData.dataSize++;
	sl_unlock(&lh);

	//添加数据
	PushInfo(Monitor_Thread);

FINAL:
	if (pThreadMsg)
	{
		ExFreePoolWithTag(pThreadMsg, NF_TAG_THREAD);
		pThreadMsg = NULL;
	}

	return OB_PREOP_SUCCESS;
}

