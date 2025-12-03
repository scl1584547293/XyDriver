#pragma once
#include <fltKernel.h>
#include "public.h"
#include "config.h"

typedef struct _REGISTERINFO
{
	//
	MonitorTypeRegistry_EM opearType;
	//线程id
	ULONG threadId;
	//操作类型
	ULONG type;
	//注册表路径句柄
	WCHARMAX object;
	//
	ULONG keyInformationClass;
	//是否64位
	ULONG wow64Flags;
	//索引
	ULONG index;
	//注册表项名
	WCHARMAX name;
	//修改数据
	char setData[MAX_PATH];
	//数据长度
	ULONG dataSize;
	//进程创建时间
	LONGLONG createTime;
}REGISTERINFO,*PREGISTERINFO;

//初始化注册表模块
NTSTATUS RegisterInit();
//清理注册表模块
VOID CleanRegister();
//释放注册表模块
VOID FreeRegister();

//回调函数
NTSTATUS
RegistryObjectCallback(
	IN PVOID                pCallbackContext,
	IN REG_NOTIFY_CLASS     notifyClass,
	IN PVOID                pArgument2
);

//从List中申请内存
PDEVBUFFER RegisterPacketAllocate(int lens);
//释放内存
void RegisterPacketFree(PDEVBUFFER packet);
//获取注册表数据
PDEVDATA GetRegisterCtx();

BOOL CheckRegConfig(REG_NOTIFY_CLASS notifyClass);

//获取数据量
VOID CheckRegistryDataNum();