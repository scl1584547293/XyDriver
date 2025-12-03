#pragma once
#include <fltKernel.h>
#include "public.h"
#include "config.h"
#include "devctrl.h"

typedef struct _FILEINFO
{
	//文件操作类型
	MonitorTypeFile_EM type;
	//线程id
	ULONG threadId;
	//文件名
	WCHARMAX fileName;
	//文件路径
	WCHARMAX filePath;
	//重命名后名字
	WCHARMAX rename;
	//进程创建时间
	LONGLONG createTime;
	//文件创建时间
	LONGLONG fileCreateTime;
}FILEINFO, *PFILEINFO;

//初始化MiniFilter
NTSTATUS MiniFilterInit(PDRIVER_OBJECT DriverObject);
//卸载MiniFilter
VOID UnloadMiniFilter();

//获取文件基本属性
BOOL FltGetFileCommonInfo(_Inout_ PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PMonitorMsg pMiniFilterMsg);

BOOL SetMiniFilterHeadList(PMonitorMsg pMiniFilterMsg);

//创建文件之后
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags);

//关闭文件之前
FLT_PREOP_CALLBACK_STATUS MiniFilterPreClose(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext);


//读取文件之前
FLT_PREOP_CALLBACK_STATUS MiniFilterPretRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext);

//写入文件之后
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags);

//设置文件属性之后
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostSetInfoMation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags);

//清理文件数据
VOID CleanMiniFilter();
//从List中申请内存
PDEVBUFFER MiniFilterPacketAllocate(int lens);
//释放内存
void MiniFilterPacketFree(PDEVBUFFER packet);
//获取文件数据
PDEVDATA GetMiniFilterCtx();

//检测数据量
VOID CheckMiniFilterDataNum();