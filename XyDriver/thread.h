#pragma once
#include <fltKernel.h>
#include "public.h"
#include "config.h"

typedef struct _THREADINFO
{
	//创建/销毁线程
	MonitorTypeThread_EM threadType;
	//线程id
	ULONG threadId;
	//进程创建时间
	LONGLONG createTime;
}THREADINFO, *PTHREADINFO;

//初始化线程模块
NTSTATUS ThreadInit();
//清理线程模块
VOID CleanThread();
//释放线程模块
VOID FreeThread();

//回调函数
VOID ThreadNotifyProcess(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

//申请内存
PDEVBUFFER ThreadPacketAllocate(int lens);
//释放内存
void ThreadPacketFree(PDEVBUFFER packet);
//获取线程数据
PDEVDATA GetThreadCtx();

//获取数据量
VOID CheckThreadDataNum();

//句柄监控回调函数
OB_PREOP_CALLBACK_STATUS PreThreadCallback(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION PreInfo);
