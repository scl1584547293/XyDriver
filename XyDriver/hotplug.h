#pragma once
#include <fltKernel.h>
#include <wdmguid.h>
#include "public.h"
#include "config.h"

typedef struct _HOTPLUGINFO
{
	MonitorTypeUSB_EM type;
	//线程id
	ULONG threadId;
	//设备符号链接的名称
	WCHARMAX symbolicLinkName;
	//设备接口的类
	GUID interfaceClassGuid;
	//进程创建时间
	LONGLONG createTime;
}HOTPLUGINFO, *PHOTPLUGINFO;

//初始化热插拔
NTSTATUS HotPlugInit(_In_ PDRIVER_OBJECT DriverObject);
//清理线程模块
VOID CleanHotPlug();
//释放线程模块
VOID FreeHotPlug();

//回调函数
NTSTATUS NotificationCallback(
	IN PVOID NotificationStructure,
	IN PVOID Context
);

//申请内存
PDEVBUFFER HotPlugPacketAllocate(int lens);
//释放内存
void HotPlugPacketFree(PDEVBUFFER packet);
//获取线程数据
PDEVDATA GetHotPlugCtx();

//检测数据量
VOID CheckHotPlugDataNum();
