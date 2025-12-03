#include "config.h"
#include <public.h>

static Config g_Configs = {0};

static KSPIN_LOCK g_configLock = 0;

NTSTATUS InitConfig()
{
	sl_init(&g_configLock);

	return STATUS_SUCCESS;
}

NTSTATUS SetConfig(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID configData = NULL;

	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		goto FINAL;

	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (NULL == inputBuffer || inputBufferLength < sizeof(g_Configs))
	{
		status = STATUS_INVALID_PARAMETER;
		goto FINAL;
	}

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_configLock,&lh);
	ULONG workMode = g_Configs[Monitor_Mode];

	RtlZeroMemory(&g_Configs,sizeof(g_Configs));
	RtlCopyMemory(&g_Configs, inputBuffer, sizeof(g_Configs));

	g_Configs[Monitor_Mode] = workMode;
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s)开关配置完成\n", __FILE__, __LINE__, __FUNCTION__));

FINAL:
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

//黑白名单配置
NTSTATUS SetWorkMode(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID configData = NULL;

	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		goto FINAL;

	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (NULL == inputBuffer || inputBufferLength < sizeof(ULONG))
	{
		status = STATUS_INVALID_PARAMETER;
		goto FINAL;
	}

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_configLock, &lh);
	g_Configs[Monitor_Mode] = *(PULONG)inputBuffer;
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s)黑白名单配置完成：%d\n", __FILE__, __LINE__, __FUNCTION__, g_Configs[Monitor_Mode]));

FINAL:
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

BOOL GetTypeConfig(ULONG type)
{
	BOOL ret = FALSE;
	if (type > Monitor_Max)
	{
		return ret;
	}
		
	switch (type)
	{
	case Monitor_Mode:
		return g_Configs[Monitor_Mode] == 0 ? FALSE : TRUE;
	case Monitor_Process:
	case Monitor_Thread:
	case Monitor_File:
	case Monitor_Registry:
	case Monitor_Socket:
	case Monitor_USB:
	case Monitor_Image:
		ret = g_Configs[type] == 0 ? FALSE : TRUE;
		return ret;
		//进程创建
	case MT_ProcessCreate:
		//进程销毁
	case MT_ProcessExit:
		//进程打开
	case MT_ProcessOpen:
		//进程运行
	case MT_ProcessStart:
		if (g_Configs[Monitor_Process] == 0)
			return FALSE;
		break;
		//线程创建
	case MT_ThreadCreate:
		//线程退出
	case MT_ThreadExit:
		//线程打开
	case MT_ThreadOpen:
		//线程运行
	case MT_ThreadStart:
		if (g_Configs[Monitor_Thread] == 0)
			return FALSE;
		break;
		//文件创建
	case MT_FileCreate:
		//文件打开
	case MT_FileOpen:
		//文件关闭
	case MT_FileClose:
		//文件读取
	case MT_FileRead:
		//文件写入
	case MT_FileWrite:
		//文件删除
	case MT_FileDelete:
		if (g_Configs[Monitor_File] == 0)
			return FALSE;
		break;
		//注册表创建
	case MT_RegCreateKey:
		//注册表打开
	case MT_RegOpenKey:
		//注册表删除项
	case MT_RegDeleteKey:
		//注册表重命名
	case MT_RenameKey:
		//注册表枚举
	case MT_RegEnumKey:
		//注册表删除值
	case MT_RegDeleteValue:
		//注册表设置值
	case MT_RegSetValue:
		//注册表查询值
	case MT_RegQueryValue:
		if (g_Configs[Monitor_Registry] == 0)
			return FALSE;
		break;
		//网络创建
	case MT_SocketCreate:
		//网络绑定端口
	case MT_SocketBind:
		//网路关闭
	case MT_SocketClose:
		//网络连接
	case MT_SocketConnect:
		//网络发送
	case MT_SocketSend:
		//网络数据接收
	case MT_SocketRecv:
		//服务端建立连接
	case MT_SocketAccept:
		if (g_Configs[Monitor_Socket] == 0)
			return FALSE;
		break;
	case MT_USBArrival:
	case MT_USBRemoval:
		if (g_Configs[Monitor_USB] == 0)
			return FALSE;
		break;
	default:
		return FALSE;
	}

	ret = g_Configs[type] == 0 ? FALSE : TRUE;

	return ret;
}

