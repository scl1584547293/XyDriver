#include "minifilter.h"
#include "devctrl.h"
#include "policy.h"

//一条数据申请内存大小
#define FILE_ALLOCATESIZE sizeof(MonitorMsg) + sizeof(FILEINFO)
#define FILE_DATAMAXNUM LIST_MAX_SIZE/FILE_ALLOCATESIZE

static NPAGED_LOOKASIDE_LIST g_miniFilterList;
static DEVDATA g_miniFilterData;

static BOOL g_IsClean = FALSE;

#define NF_TAG_FILE 'MgTg'
#define NF_TAG_FILE_BUF 'MbTg'

PFLT_FILTER g_FilterHandle = NULL;
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	//文件打开、文件创建
	{ IRP_MJ_CREATE,
	0,
	NULL,
	MiniFilterPostCreate },

	//文件读取
	{ IRP_MJ_READ,
	0,
	MiniFilterPretRead,
	NULL },

	//文件写入
	{ IRP_MJ_WRITE,
	0,
	NULL,
	MiniFilterPostWrite },

	//文件属性修改（暂时只做删除）
	{ IRP_MJ_SET_INFORMATION,
	0,
	NULL,
	MiniFilterPostSetInfoMation },

#ifndef WINXP
	//文件关闭
	{ IRP_MJ_CLOSE,
	0,
	MiniFilterPreClose,
	NULL},
#endif

	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks
	
	UnloadMiniFilter,                           //  MiniFilterUnload

	NULL,                    //  InstanceSetup
	NULL,            //  InstanceQueryTeardown
	NULL,            //  InstanceTeardownStart
	NULL,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

//初始化MiniFilter模块
NTSTATUS MiniFilterInit(PDRIVER_OBJECT DriverObject)
{
	//UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = STATUS_SUCCESS;

	sl_init(&g_miniFilterData.lock);
	InitializeListHead(&g_miniFilterData.pending);

	ExInitializeNPagedLookasideList(
		&g_miniFilterList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);
	
	g_IsClean = TRUE;

	//注册MiniFilter
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
	if (NT_SUCCESS(status)) 
	{
		//开始MiniFilter
		status = FltStartFiltering(g_FilterHandle);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("%s:%d(%s) [MiniFilter]FltStartFiltering err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
			//卸载MiniFilter
			FltUnregisterFilter(g_FilterHandle);
			g_FilterHandle = NULL;
			return status;
		}
		KdPrint(("%s:%d(%s) [MiniFilter]MiniFilterInit success\n", __FILE__, __LINE__, __FUNCTION__));
	}
	else
	{
		KdPrint(("%s:%d(%s) [MiniFilter]MiniFilterInit error:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
	}

	
	return status;
}

//清理MiniFilter
VOID CleanMiniFilter()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_miniFilterData.lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_miniFilterData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_miniFilterData.pending);
			if (!pData)
				break;
			g_miniFilterData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			MiniFilterPacketFree(pData);
			pData = NULL;
			sl_lock(&g_miniFilterData.lock, &lh);
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

//卸载MiniFilter
VOID UnloadMiniFilter()
{
	if (!g_IsClean)
		return;

	CleanMiniFilter();
	ExDeleteNPagedLookasideList(&g_miniFilterList);

	if (g_FilterHandle)
	{
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = NULL;
	}

	return;
}

//获取文件基本属性
BOOL FltGetFileCommonInfo(_Inout_ PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PMonitorMsg pMiniFilterMsg)
{
	if (NULL == pMiniFilterMsg || KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return FALSE;
	}

	NTSTATUS status = STATUS_SUCCESS;

	PFILEINFO pMiniFilterInfo = (PFILEINFO)pMiniFilterMsg->data;
	if (!pMiniFilterInfo)
		return FALSE;

	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	//注册
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED /*| FLT_FILE_NAME_QUERY_DEFAULT*/, &FileNameInfo);
	if (!NT_SUCCESS(status))
	{
		//KdPrint(("%s:%d(%s) [MiniFilter]FltGetFileNameInformation err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		return FALSE;
	}

	//增加引用计数
	//FltReferenceFileNameInformation(FileNameInfo);

	//Data中有些获取不到process数据，可能会崩溃！！
	//PEPROCESS process = FltGetRequestorProcess(Data);
	//if (process == NULL)
	//{
	//	//释放
	//	FltReleaseFileNameInformation(FileNameInfo);
	//	return FALSE;
	//}
	
	//FltReferenceFileNameInformation(FileNameInfo);
	//if (NT_SUCCESS(Data->IoStatus.Status))
	//读取和写入冲突，会导致死锁
	if(pMiniFilterInfo->type != MT_FileRead && pMiniFilterInfo->type != MT_FileWrite)
	{
		FILE_BASIC_INFORMATION fileInfo;
		ULONG returnLength;
		//可能导致死锁，需要注意
		status = FltQueryInformationFile(
			Data->Iopb->TargetInstance,
			Data->Iopb->TargetFileObject,
			&fileInfo,
			sizeof(fileInfo),
			FileBasicInformation,
			&returnLength
		);

		//FltReleaseFileNameInformation(FileNameInfo);

		if (NT_SUCCESS(status))
		{
			// 创建时间
			LONGLONG createTime = 0;
			RtlCopyMemory(&createTime, &fileInfo.CreationTime, sizeof(LONGLONG));
			if (createTime != 0)
			{
				pMiniFilterInfo->fileCreateTime = createTime / 10000000 - 11644473600;
			}
		}
	}

	//解析
	status = FltParseFileNameInformation(FileNameInfo);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [MiniFilter]FltParseFileNameInformation\n", __FILE__, __LINE__, __FUNCTION__));
		//释放
		FltReleaseFileNameInformation(FileNameInfo);
		return FALSE;
	}

	if (FileNameInfo->Name.Length > 0 && FileNameInfo->Name.Length < sizeof(WCHARMAX))
	{
		RtlCopyMemory(pMiniFilterInfo->fileName,FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);

		//文件路径转码
		//WCHAR ntName[MAX_PATH] = { 0 };
		//if (GetNTLinkName(pMiniFilterInfo->fileName, ntName) && ntName[0] != L'\0')
		//{
		//	RtlCopyMemory(pMiniFilterInfo->fileName, ntName, MAX_PATH * sizeof(WCHAR));
		//}
	}

	if (FileNameInfo->ParentDir.Length > 0 && FileNameInfo->ParentDir.Length < sizeof(WCHARMAX))
	{
		RtlCopyMemory(pMiniFilterInfo->filePath,FileNameInfo->ParentDir.Buffer, FileNameInfo->ParentDir.Length);
	}

	//释放引用
	FltReleaseFileNameInformation(FileNameInfo);

	//进程id
	//pMiniFilterInfo->pid = PsGetProcessId(process);
	////进程名
	//UCHAR* processName = PsGetProcessImageFileName(process);
	//if(processName)
	//	RtlCopyMemory(pMiniFilterInfo->processPath, processName, strlen(processName));


	//线程id
	pMiniFilterInfo->threadId = (DWORD)PsGetCurrentThreadId();
	pMiniFilterMsg->common.pid = (DWORD)PsGetCurrentProcessId();

	GetCurrentTimeString(&pMiniFilterMsg->common.time);

	if (pMiniFilterMsg->common.pid == 0 || pMiniFilterMsg->common.pid == (DWORD)PsGetProcessId(PsInitialSystemProcess))
	{	
		return FALSE;
	}

	WCHARMAX processPath = { 0 };
	if (!QueryProcessNamePath(pMiniFilterMsg->common.pid, processPath, sizeof(processPath)))
	{
		return FALSE;
	}

	RtlCopyMemory(pMiniFilterMsg->common.exe, processPath, sizeof(WCHARMAX));

	//根据进程id获取进程名
	GetProcessNameByPID(pMiniFilterMsg->common.pid, pMiniFilterMsg->common.comm, sizeof(pMiniFilterMsg->common.comm),&pMiniFilterMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)pMiniFilterMsg->common.pid, &pMiniFilterInfo->createTime);

	BOOL isWhite = GetTypeConfig(Monitor_Mode);
	//黑名单
	if (!isWhite)
	{
		if (IsAllowData(POLICY_EXE_LIST, pMiniFilterMsg->common.comm, FALSE) ||
			IsAllowData(POLICY_EXE_LIST, pMiniFilterMsg->common.exe, TRUE) ||
			IsAllowData(POLICY_FILE_LIST, pMiniFilterInfo->fileName, TRUE))
		{
			return TRUE;
		}
		return FALSE;
	}
	//白名单
	else
	{
		if ((!IsAllowData(POLICY_EXE_LIST, pMiniFilterMsg->common.exe, TRUE) || 
			!IsAllowData(POLICY_EXE_LIST, pMiniFilterMsg->common.comm, FALSE)) 
			&& !IsAllowData(POLICY_FILE_LIST, pMiniFilterInfo->fileName, TRUE))
		{
			return FALSE;
		}
		return TRUE;
	}

	//return FALSE;
}

//存放数据到List
BOOL SetMiniFilterHeadList(PMonitorMsg pMiniFilterMsg)
{
	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(FILEINFO);

	PDEVBUFFER pInfo = (PDEVBUFFER)MiniFilterPacketAllocate(FILE_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [MiniFilter]MiniFilterPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		return FALSE;
	}

	RtlCopyMemory(pInfo->dataBuffer, pMiniFilterMsg, FILE_ALLOCATESIZE);

	//检测数据量
	CheckMiniFilterDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_miniFilterData.lock, &lh);
	InsertHeadList(&g_miniFilterData.pending, &pInfo->pEntry);

	g_miniFilterData.dataSize++;
	sl_unlock(&lh);

	PushInfo(Monitor_File);

	return TRUE;
}

//创建文件之后
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCreate(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_In_opt_ PVOID CompletionContext,
		_In_ FLT_POST_OPERATION_FLAGS Flags
		)
{
	PMonitorMsg pMiniFilterMsg = NULL;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL || !NT_SUCCESS(Data->IoStatus.Status))
		goto FINAL;

	ULONG fileType = MT_FileCreate;
	//文件操作类型
	switch (Data->IoStatus.Information)
	{
		//打开文件
	case FILE_OPENED:
		fileType = MT_FileOpen;
		if (!GetTypeConfig(MT_FileOpen))
			goto FINAL;
		break;
		//创建文件
	case FILE_CREATED:
		if (!GetTypeConfig(MT_FileCreate))
			goto FINAL;
		break;
	default:
		goto FINAL;
	}


	//FILE_STANDARD_INFORMATION StdInfo;
	//ULONG nRetLength = 0;
	//NTSTATUS ns = FltQueryInformationFile(FltObjects->Instance,
	//	FltObjects->FileObject, &StdInfo, sizeof(FILE_STANDARD_INFORMATION),
	//	FileStandardInformation, &nRetLength);
	//if (NT_SUCCESS(ns))
	//{
	//	//目录
	//	if (StdInfo.Directory)
	//	{
	//		goto FINAL;
	//	}
	//}

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(FILEINFO);

	pMiniFilterMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, FILE_ALLOCATESIZE,NF_TAG_FILE);
	if (!pMiniFilterMsg)
		goto FINAL;
	RtlZeroMemory(pMiniFilterMsg, FILE_ALLOCATESIZE);

	pMiniFilterMsg->common.type = Monitor_File;

	PFILEINFO pMiniFilterInfo = (PFILEINFO)pMiniFilterMsg->data;
	if (!pMiniFilterInfo)
		goto FINAL;
	pMiniFilterInfo->type = fileType;

	//获取通用数据
	if (!FltGetFileCommonInfo(Data, FltObjects, pMiniFilterMsg))
	{
		//KdPrint(("%s:%d(%s) [MiniFilter]FltGetFileCommonInfo err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	KdPrint(("%s:%d(%s) [createfile] pid:%d,name:%S,path:%S\n",__FILE__,__LINE__, __FUNCTION__, 
		pMiniFilterMsg->common.pid, pMiniFilterInfo->fileName, pMiniFilterInfo->filePath));

	//
	SetMiniFilterHeadList(pMiniFilterMsg);
	

FINAL:
	if (pMiniFilterMsg)
	{
		ExFreePoolWithTag(pMiniFilterMsg,NF_TAG_FILE);
		pMiniFilterMsg = NULL;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}


//关闭文件之后
FLT_PREOP_CALLBACK_STATUS MiniFilterPreClose(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext)
{
	PMonitorMsg pMiniFilterMsg = NULL;
	if (!GetTypeConfig(MT_FileClose) || KeGetCurrentIrql() != PASSIVE_LEVEL)
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(FILEINFO);

	pMiniFilterMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, FILE_ALLOCATESIZE,NF_TAG_FILE);
	if (!pMiniFilterMsg)
		goto FINAL;

	RtlZeroMemory(pMiniFilterMsg, FILE_ALLOCATESIZE);

	pMiniFilterMsg->common.type = Monitor_File;

	PFILEINFO pMiniFilterInfo = (PFILEINFO)pMiniFilterMsg->data;
	if (!pMiniFilterInfo)
		goto FINAL;
	pMiniFilterInfo->type = MT_FileClose;

	//获取通用数据
	if (!FltGetFileCommonInfo(Data, FltObjects, pMiniFilterMsg))
	{
		//KdPrint(("%s:%d(%s) [MiniFilter]FltGetFileCommonInfo err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	KdPrint(("%s:%d(%s) [closefile] pid:%d,processName:%s,name:%S,path:%S\n", __FILE__, __LINE__, __FUNCTION__,
		pMiniFilterMsg->common.pid, pMiniFilterMsg->common.comm,pMiniFilterInfo->fileName, pMiniFilterInfo->filePath));
	//
	SetMiniFilterHeadList(pMiniFilterMsg);

FINAL:
	if (pMiniFilterMsg)
	{
		ExFreePoolWithTag(pMiniFilterMsg,NF_TAG_FILE);
		pMiniFilterMsg = NULL;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//读取文件之前
FLT_PREOP_CALLBACK_STATUS MiniFilterPretRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext)
{
	PMonitorMsg pMiniFilterMsg = NULL;

	if(!GetTypeConfig(MT_FileRead) || KeGetCurrentIrql() != PASSIVE_LEVEL)
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(FILEINFO);

	pMiniFilterMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, FILE_ALLOCATESIZE, NF_TAG_FILE);
	if (!pMiniFilterMsg)
		goto FINAL;

	RtlZeroMemory(pMiniFilterMsg, FILE_ALLOCATESIZE);

	pMiniFilterMsg->common.type = Monitor_File;


	//获取通用数据
	PFILEINFO pMiniFilterInfo = (PFILEINFO)pMiniFilterMsg->data;
	if (!pMiniFilterInfo)
		goto FINAL;
	pMiniFilterInfo->type = MT_FileRead;


	//获取通用数据
	if (!FltGetFileCommonInfo(Data, FltObjects, pMiniFilterMsg))
	{
		//KdPrint(("%s:%d(%s) [MiniFilter]FltGetFileCommonInfo err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	KdPrint(("%s:%d(%s) [readfile] pid:%d,processName:%s,name:%S,path:%S\n", __FILE__, __LINE__, __FUNCTION__, 
		pMiniFilterMsg->common.pid, pMiniFilterMsg->common.comm, pMiniFilterInfo->fileName, pMiniFilterInfo->filePath));

	SetMiniFilterHeadList(pMiniFilterMsg);

FINAL:
	if (pMiniFilterMsg)
	{
		ExFreePoolWithTag(pMiniFilterMsg, NF_TAG_FILE);
		pMiniFilterMsg = NULL;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//写入文件之后
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags)
{
	PMonitorMsg pMiniFilterMsg = NULL;

	if (!GetTypeConfig(MT_FileWrite) || KeGetCurrentIrql() != PASSIVE_LEVEL)
		goto FINAL;;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(FILEINFO);

	pMiniFilterMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, FILE_ALLOCATESIZE, NF_TAG_FILE);
	if (!pMiniFilterMsg)
		goto FINAL;

	RtlZeroMemory(pMiniFilterMsg, FILE_ALLOCATESIZE);

	pMiniFilterMsg->common.type = Monitor_File;

	PFILEINFO pMiniFilterInfo = (PFILEINFO)pMiniFilterMsg->data;
	if (!pMiniFilterInfo)
		goto FINAL;
	pMiniFilterInfo->type = MT_FileWrite;


	//获取通用数据
	if (!FltGetFileCommonInfo(Data, FltObjects,pMiniFilterMsg))
	{
		//KdPrint(("%s:%d(%s) [MiniFilter]FltGetFileCommonInfo err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	KdPrint(("%s:%d(%s) [writefile] pid:%d,name:%S,processName:%s,processPath:%S\n", __FILE__, __LINE__, __FUNCTION__,
		pMiniFilterMsg->common.pid, pMiniFilterInfo->fileName, pMiniFilterMsg->common.comm, pMiniFilterMsg->common.exe));

	SetMiniFilterHeadList(pMiniFilterMsg);

FINAL:
	if (pMiniFilterMsg)
	{
		ExFreePoolWithTag(pMiniFilterMsg,NF_TAG_FILE);
		pMiniFilterMsg = NULL;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//设置文件属性之后
//TODO
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostSetInfoMation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags)
{
	PMonitorMsg pMiniFilterMsg = NULL;
	if (!GetTypeConfig(MT_FileDelete) || KeGetCurrentIrql() != PASSIVE_LEVEL)
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(FILEINFO);

	pMiniFilterMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, FILE_ALLOCATESIZE, NF_TAG_FILE);
	if (!pMiniFilterMsg)
		goto FINAL;

	RtlZeroMemory(pMiniFilterMsg, FILE_ALLOCATESIZE);

	pMiniFilterMsg->common.type = Monitor_File;

	PFILEINFO pMiniFilterInfo = (PFILEINFO)pMiniFilterMsg->data;
	if (!pMiniFilterInfo)
		goto FINAL;
	pMiniFilterInfo->type = MT_FileDelete;

	
	//获取通用数据
	if (!FltGetFileCommonInfo(Data, FltObjects, pMiniFilterMsg))
	{
		//KdPrint(("%s:%d(%s) [MiniFilter]FltGetFileCommonInfo err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	PFILE_BASIC_INFORMATION pBasicInfomation;
	TIME_FIELDS createTm, lastAccessTm, lastWriteTm, changeTm;

	PFILE_DISPOSITION_INFORMATION pDispositionInfomation;
	PFILE_RENAME_INFORMATION pRenameInfomation;
	WCHAR *fileName = NULL;

	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileDispositionInformation)
		goto FINAL;

	pDispositionInfomation = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	if (!pDispositionInfomation->DeleteFile)
		goto FINAL;

	//switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
	//{
	//	//基础属性
	//case FileBasicInformation:
	//	pBasicInfomation = (PFILE_BASIC_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

	//	LargeToTime(pBasicInfomation->CreationTime,&createTm);
	//	LargeToTime(pBasicInfomation->LastAccessTime, &lastAccessTm);
	//	LargeToTime(pBasicInfomation->LastWriteTime, &lastWriteTm);
	//	LargeToTime(pBasicInfomation->ChangeTime, &changeTm);

	//	//KdPrint(("创建时间:%4d-%2d-%2d %2d:%2d:%2d,\
	//	//		最后访问时间:%4d-%2d-%2d %2d:%2d:%2d,\
	//	//		最后写入时间:%4d-%2d-%2d %2d:%2d:%2d,\
	//	//		修改时间:%4d-%2d-%2d %2d:%2d:%2d\n",
	//	//	createTm.Year, createTm.Month, createTm.Day, createTm.Hour, createTm.Minute, createTm.Second,
	//	//	lastAccessTm.Year, lastAccessTm.Month, lastAccessTm.Day, lastAccessTm.Hour, lastAccessTm.Minute, lastAccessTm.Second,
	//	//	lastWriteTm.Year, lastWriteTm.Month, lastWriteTm.Day, lastWriteTm.Hour, lastWriteTm.Minute, lastWriteTm.Second,
	//	//	changeTm.Year, changeTm.Month, changeTm.Day, changeTm.Hour, changeTm.Minute, changeTm.Second));
	//	break;
	//	//关闭文件时是否删除
	//case FileDispositionInformation:
	//	pDispositionInfomation = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	//	if (pDispositionInfomation->DeleteFile)
	//		KdPrint(("文件需要删除\n"));
	//	else
	//		KdPrint(("文件不需要删除\n"));
	//	break;
	//	//重命名文件
	//case FileRenameInformation:
	//	pRenameInfomation = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	//	if (pRenameInfomation->FileNameLength > 0 && pRenameInfomation->FileNameLength < sizeof(WCHARMAX))
	//	{
	//		RtlCopyMemory(pMiniFilterInfo->rename, pRenameInfomation->FileName, pRenameInfomation->FileNameLength);
	//		//KdPrint(("重命名文件：%S\n", pMiniFilterInfo->rename));
	//	}
	//	break;
	//}

	KdPrint(("%s:%d(%s) [deletefile] pid:%d,proName:%S,path:%S\n", __FILE__, __LINE__, __FUNCTION__,
		pMiniFilterMsg->common.pid, pMiniFilterMsg->common.exe,pMiniFilterInfo->fileName));

	SetMiniFilterHeadList(pMiniFilterMsg);

FINAL:
	if (pMiniFilterMsg)
	{
		ExFreePoolWithTag(pMiniFilterMsg, NF_TAG_FILE);
		pMiniFilterMsg = NULL;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//从List中申请内存
PDEVBUFFER MiniFilterPacketAllocate(int lens)
{
	PDEVBUFFER pRegbuf = NULL;

	if (lens <= 0)
		return pRegbuf;

	pRegbuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_miniFilterList);
	if (!pRegbuf)
		return pRegbuf;

	RtlZeroMemory(pRegbuf, sizeof(DEVBUFFER));

	pRegbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_FILE_BUF);
	if (!pRegbuf->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_miniFilterList, pRegbuf);
		pRegbuf = NULL;
		return pRegbuf;
	}
	pRegbuf->dataLength = lens;
	RtlZeroMemory(pRegbuf->dataBuffer,lens);
	
	return pRegbuf;
}

//释放内存
void MiniFilterPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;
	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_FILE_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_miniFilterList, packet);
}

//获取存储数据信息
PDEVDATA GetMiniFilterCtx()
{
	return &g_miniFilterData;
}

//检测数据量
VOID CheckMiniFilterDataNum()
{
	if (g_miniFilterData.dataSize > FILE_DATAMAXNUM)
	{
		CleanMiniFilter();

		//KLOCK_QUEUE_HANDLE lh;
		//sl_lock(&g_miniFilterData.lock, &lh);
		//g_miniFilterData.dataSize = 0;
		//sl_unlock(&lh);
	}
}