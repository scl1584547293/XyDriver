#pragma once
#include <fltKernel.h>
#include "public.h"
#include "devctrl.h"

typedef struct _PROCESSINFO
{
	MonitorTypeProcess_EM processType;
	//线程id
	ULONG threadId;
	ULONG pThreadId;
	//父进程路径
	WCHARMAX parenPath;
	//进程命令行
	WCHARMAX commandLine;
	//进程创建时间
	LONGLONG createTime;
}PROCESSINFO, *PPROCESSINFO;

//初始化进程模块
NTSTATUS ProcessInit();
//清理进程模块
VOID CleanProcess();
//释放进程模块
VOID FreeProcess();

//内存申请
PDEVBUFFER ProcessPacketAllocate(int lens);
//释放内存
void ProcessPacketFree(PDEVBUFFER packet);
//获取进程信息
PDEVDATA GetProcessCtx();

//句柄监控回调函数
OB_PREOP_CALLBACK_STATUS PreProcessCallback(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION PreInfo);

//检测数据量
VOID CheckProcessDataNum();
