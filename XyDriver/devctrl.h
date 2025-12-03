#pragma once
#include <fltKernel.h>
#include <minwindef.h>
#include "config.h"

//#define WINXP

#define NF_PACKET_BUF_SIZE 1024*1024 //1M
#define LIST_MAX_SIZE 10*NF_PACKET_BUF_SIZE //10M

typedef UNALIGNED struct _NF_BUFFERS
{
	unsigned __int64 inBuf;
	unsigned __int64 inBufLen;
	unsigned __int64 outBuf;
	unsigned __int64 outBufLen;
} NF_BUFFERS, *PNF_BUFFERS;

typedef struct _SHARED_MEMORY
{
	PMDL					mdl;
	PVOID					userVa;
	PVOID					kernelVa;
	UINT64					bufferLength;
} SHARED_MEMORY, *PSHARED_MEMORY;

//enum _NF_DATA_CODE
//{
//	//进程数据
//	NF_PROCESS_INFO = 150,
//	//线程数据
//	NF_THREAD_INFO,
//	//注册表数据
//	NF_REGISTERTAB_INFO,
//	//文件数据
//	NF_FILE_INFO,
//	//网络数据
//	NF_NETWORK_INFO,
//	//设备热插拔数据
//	NF_HOTPLUG_INFO,
//}NF_DATA_CODE;

typedef struct _NF_QUEUE_ENTRY
{
	LIST_ENTRY		entry;
	int				code;
} NF_QUEUE_ENTRY, *PNF_QUEUE_ENTRY;

typedef UNALIGNED struct _NF_DATA
{
	//数据类型
	//int				code;
	//int				id;
	//数据长度
	unsigned long	bufferSize;
	//数据
	char 			buffer[1];
} NF_DATA, *PNF_DATA;

typedef UNALIGNED struct _NF_READ_RESULT
{
	unsigned __int64 length;
} NF_READ_RESULT, *PNF_READ_RESULT;


typedef struct _MonitorMsgCommon {
	MonitorType_EM type;      //行为类型
	int uid;                  //用户ID
	char exe[512];            //进程可执行文件
	int pid;                  //进程ID
	int ppid;                 //父进程ID
	int pgid;                 //进程组ID
	int tgid;                 //任务组ID
	char comm[32];            //进程名
	long long time;			  //时间
} MonitorMsgCommon, *PMonitorMsgCommon;

typedef struct _MonitorMsg {
	MonitorMsgCommon common; //公共部分
	char data[0];              //数据部分
} MonitorMsg, *PMonitorMsg;


//初始化进程信息
NTSTATUS DevThreadInit();
//初始化
NTSTATUS DevInit(PDRIVER_OBJECT DriverObject);
//清理
VOID DevClean();
//关闭
NTSTATUS DevClose(PIRP irp);
//释放
VOID DevFree(PDRIVER_OBJECT pDriverObject);

//驱动读取IRP
NTSTATUS DriverRead(PIRP irp, PIO_STACK_LOCATION irpSp);
VOID DriverCancelRead(IN PDEVICE_OBJECT deviceObject, IN PIRP irp);

//获取数据
UINT64 FillBuffer();

//结束读取
void CancelPendingReads();
//读取数据
void ServiceReads();
//处理线程
void  IoThread(void* StartContext);
//驱动结束
VOID SetShutdown();
BOOL IsShutdown();

//打开共享内存
NTSTATUS OpenShareMem(PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp);
//创建共享内存
NTSTATUS CreateSharedMemory(PSHARED_MEMORY pSharedMemory, ULONG len);
//释放共享内存
VOID FreeSharedMemory(PSHARED_MEMORY pSharedMemory);

//存放数据
void PushInfo(int code);

//VOID SetWorkStatus(BOOLEAN status);
//BOOL GetWorkStatus();

////////////////////////////////////////////////////////////////////////
//抛出数据
NTSTATUS PopInfo(UINT64* pOffset, int typeCode);