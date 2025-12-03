#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "minifilter.h"
#include "process.h"
#include "thread.h"
#include "register.h"
#include "devctrl.h"
#include "policy.h"
#include "config.h"

#include "tdi.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
PKEVENT g_pKernelEvent = NULL;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry (_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath);
NTSTATUS XyDriverUnload (PDRIVER_OBJECT Driver);
NTSTATUS DriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

EXTERN_C_END


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, XyDriverUnload)
#pragma alloc_text(PAGE, DriverDispatch)
#endif

//驱动名
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\XyDriver");
//驱动设备对象名
UNICODE_STRING DeviceLinkName = RTL_CONSTANT_STRING(L"\\??\\XyDriverLink");
//驱动设备对象名
PUNICODE_STRING g_IoctlDeviceSymlink = NULL;
//驱动句柄
PDEVICE_OBJECT g_DeviceObject = NULL;


//#ifndef _WIN64
//#pragma pack(1)                               
//#endif
//typedef struct _LDR_DATA_TABLE_ENTRY
//{
//	LIST_ENTRY InLoadOrderLinks;
//	LIST_ENTRY InMemoryOrderLinks;
//	LIST_ENTRY InInitializationOrderLinks;
//	PVOID DllBase;
//	PVOID EntryPoint;
//	ULONG SizeOfImage;
//	UNICODE_STRING FullDllName;
//	UNICODE_STRING BaseDllName;
//	ULONG Flags;
//	USHORT LoadCount;
//	USHORT TlsIndex;
//	union
//	{
//		LIST_ENTRY HashLinks;
//		struct
//		{
//			PVOID SectionPointer;
//			ULONG CheckSum;
//		};
//	};
//	union
//	{
//		ULONG TimeDateStamp;
//		PVOID LoadedImports;
//	};
//	PVOID EntryPointActivationContext;
//	PVOID PatchInformation;
//	LIST_ENTRY ForwarderLinks;
//	LIST_ENTRY ServiceTagLinks;
//	LIST_ENTRY StaticLinks;
//} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//#ifndef _WIN64
//#pragma pack()
//#endif

//主函数
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath)
{
	KdPrint(("DriverEntry\n"));
    NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER( RegistryPath );

//#ifdef DBG
//	PLDR_DATA_TABLE_ENTRY ldr;
//	ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
//	ldr->Flags |= 0x20;
//#endif
	
	DriverObject->DriverUnload = XyDriverUnload;

	//MiniFilter和网络的不能放在一起，而且MiniFilter必须在创建驱动链接之前！！！！
	//不要问我为什么，这是测试多次、经历过多次系统蓝屏之后找出来！！！！-_-
	status = MiniFilterInit(DriverObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("MiniFilterInit is error\n"));
		UnloadMiniFilter();
		XyDriverUnload(DriverObject);
		return status;
	}
	KdPrint(("MiniFilterInit success\n"));
	
	//创建设备
	status = IoCreateDevice(DriverObject,0,&g_DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE, &g_DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) IoCreateDevice is error\n", __FILE__, __LINE__, __FUNCTION__));
		return status;
	}
	
	g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	//创建设备对象
	status = IoCreateSymbolicLink(&DeviceLinkName,&g_DeviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
		KdPrint(("%s:%d(%s) IoCreateSymbolicLink is error\n", __FILE__, __LINE__, __FUNCTION__));
		return status;
	}

	g_IoctlDeviceSymlink = &DeviceLinkName;
	g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	/*
		以直接I/O的方式与应用层通信，适用于大数据（一般一页内存（4k）以上）
		一页内存（4k）以下的可以使用缓存I/O，DO_BUFFERED_IO
		原因：缓存I/O需要经常进行缓冲区的内存复制，对于大数据而言增加系统的消耗，而直接I/O没有缓冲区的复制过程，所以更快
	*/
	g_DeviceObject->Flags |= DO_DIRECT_IO;


	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)DriverDispatch;
	}

	status = DevInit(DriverObject);
	if (!NT_SUCCESS(status))
	{
		UnloadMiniFilter();
		XyDriverUnload(DriverObject);
	}
	
    return status;
}

//卸载驱动
NTSTATUS XyDriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	NTSTATUS status = STATUS_SUCCESS;
	KdPrint(("XyDriverUnload\n"));

	//释放模块
	DevFree(pDriverObject);

	//if (g_IoctlDeviceSymlink)
	//{
	//	status = IoDeleteSymbolicLink(g_IoctlDeviceSymlink);
	//	g_IoctlDeviceSymlink = NULL;
	//}

	//增加ndis之后这里需要循环删除
	//PDEVICE_OBJECT		pDeviceObject, pNextDeviceObject;
	//pDeviceObject = pNextDeviceObject = pDriverObject->DeviceObject;
	//while (pNextDeviceObject != NULL)
	//{
	//	pNextDeviceObject = pDeviceObject->NextDevice;

	//	IoDeleteDevice(pDeviceObject);
	//	pDeviceObject = pNextDeviceObject;
	//}

	if (g_IoctlDeviceSymlink)
	{
		status = IoDeleteSymbolicLink(g_IoctlDeviceSymlink);
		g_IoctlDeviceSymlink = NULL;
	}

	if (g_DeviceObject)
	{
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = NULL;
	}

    return status;
}

//打开共享内存
#define OPEN_SHAREMEM CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)
//发送开关数据
#define SENDCONFIG_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_WRITE_DATA)
//发送黑白名单配置
#define SENDWORKMODE_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_WRITE_DATA)
//发送策略数据
#define SENDPOLICY_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_WRITE_DATA)

//消息处理
NTSTATUS DriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	ASSERT(irpSp);
	ULONG_PTR retuenLenth = 0;

#ifdef WINXP
	if (IsTdiObject(DeviceObject))
	{
		return TdiDeviceDispatch(DeviceObject, Irp);
	}
#endif

	switch (irpSp->MajorFunction)
	{
		//读取数据
	case IRP_MJ_READ:
		KdPrint(("====IRP_MJ_READ\n"));
		return DriverRead(Irp, irpSp);
		//关闭驱动
	case IRP_MJ_CLOSE:
		KdPrint(("====IRP_MJ_CLOSE\n"));
		return DevClose(Irp);
		//自定义消息
	case IRP_MJ_DEVICE_CONTROL:
	{
		//PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
		//ULONG inLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		//ULONG outLengrh = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

		HANDLE hEvent = NULL;
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
			//打开共享内存
		case OPEN_SHAREMEM:
			KdPrint(("====OPEN_SHAREMEM\n"));
			return OpenShareMem(DeviceObject, Irp, irpSp);
		case SENDCONFIG_CTL:
			KdPrint(("====SENDCONFIG_CTL\n"));
			return SetConfig(Irp, irpSp);
		case SENDWORKMODE_CTL:
			KdPrint(("====SENDWORKMODE_CTL\n"));
			return SetWorkMode(Irp, irpSp);
			//获取进程配置
		case SENDPOLICY_CTL:
			KdPrint(("====SENDPOLICY_CTL\n"));
			return SetPolicy(Irp, irpSp);
			//获取文件配置
		//case SENDFILE_CTL:
		//	return SetFileConfig(Irp, irpSp);
			//配置获取完成
		//case SENDFSTART_CTL:
		//	SetWorkStatus(TRUE);
		//	KdPrint(("%s:%d(%s):开始采集\n",__FILE__,__LINE__,__FUNCTION__));
		//	break;
		//case SENDFSTOP_CTL:
		//	SetWorkStatus(FALSE);
		//	KdPrint(("%s:%d(%s):停止采集\n", __FILE__, __LINE__, __FUNCTION__));
		//	break;
		}
	}
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	

	return STATUS_SUCCESS;
}
