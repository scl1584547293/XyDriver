#pragma once
#include <fltKernel.h>
#include <minwindef.h>
#include <tdikrnl.h>
#include "network.h"

#define TDI_ADDRESS_INFO_MAX (sizeof(TDI_ADDRESS_INFO) - 1 + TDI_ADDRESS_LENGTH_OSI_TSAP)

typedef struct _COMPLETION
{
	PIO_COMPLETION_ROUTINE	routine;
	PVOID					context;
}COMPLETION,*PCOMPLETION;

typedef struct _TDI_CREATE_ADDROBJ2_CTX 
{
	PTDI_ADDRESS_INFO tai;
	PFILE_OBJECT fileobj;
} TDI_CREATE_ADDROBJ2_CTX,*PTDI_CREATE_ADDROBJ2_CTX;

typedef struct _TDI_SKIP_CTX {
	PIO_COMPLETION_ROUTINE	old_cr;			/* old (original) completion routine */
	PVOID					old_context;	/* old (original) parameter for old_cr */
	PIO_COMPLETION_ROUTINE	new_cr;			/* new (replaced) completion routine */
	PVOID					new_context;	/* new (replaced) parameter for new_cr */
	PFILE_OBJECT			fileobj;		/* FileObject from IO_STACK_LOCATION */
	PDEVICE_OBJECT			new_devobj;		/* filter device object */
	UCHAR					old_control;	/* old (original) irps->Control */
} TDI_SKIP_CTX,*PTDI_SKIP_CTX;

enum {
	FILTER_ALLOW = 1,
	FILTER_DENY,
	FILTER_PACKET_LOG,
	FILTER_PACKET_BAD,
	FILTER_DISCONNECT
};

typedef struct _TDILISTDATA {
	LIST_ENTRY pending;
	PFILE_OBJECT fileobj;
	PFILE_OBJECT associateFileObj;

	//进程id
	DWORD	pid;
	//父进程id
	DWORD pPid;
	//线程id
	DWORD threadId;
	//进程名
	char processName[32];
	//进程路径
	char processPath[512];
	//进程创建时间
	ULONGLONG createTime;
	//协议名
	WCHAR protocolName[12];

	//源ip
	DWORD localIp;
	//源端口
	DWORD localPort;
	//目的ip
	DWORD remoteIP;
	//目的端口
	DWORD remotePort;
}TDILISTDATA, *PTDILISTDATA;


//初始化Tdi
NTSTATUS TdiInit(_In_ PDRIVER_OBJECT pDeviceObject);
//判断是否是Tdi
BOOL IsTdiObject(_In_ PDEVICE_OBJECT pDeviceObject);
//绑定设备
NTSTATUS TdiAttachDevice(_In_ PDRIVER_OBJECT pDriverObject, _Out_ PDEVICE_OBJECT *fltobj, _Out_ PDEVICE_OBJECT *oldobj, _In_ wchar_t *devname);
//总体的分发函数
NTSTATUS TdiDeviceDispatch(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
//结束Tdi的irp
NTSTATUS TdiDispatchComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ int filter, _In_ PIO_COMPLETION_ROUTINE cr, _In_ PVOID context);

//
NTSTATUS TdiGenericComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context);
//
NTSTATUS TdiSkipComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context);

//IRP_MJ_CREATE
int TdiCreate(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _Out_ PCOMPLETION pCompletion);
//IRP_MJ_CREATE完成函数
NTSTATUS TdiCreateComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context);
NTSTATUS TdiCreateComplete2(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context);

int TdiInternal(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps,_Out_ PCOMPLETION pCompletion);
//TDI_ASSOCIATE_ADDRESS	端口绑定
int TdiAssociateAddress(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);
//TDI_CONNECT
int TdiConnect(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);
//TDI_SEND
int TdiSend(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);
//TDI_SEND_DATAGRAM
int TdiSendDataGram(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);
//TDI_RECEIVE
NTSTATUS TdiReceiveComplete(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp, IN PVOID Context);
int TdiReceive(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);
//TDI_RECEIVE_DATAGRAM
int TdiReceiveDataGram(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);
//TDI_DISCONNECT
int TdiDisConnect(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion);

//清理Tdi模块
VOID CleanTdi();
//清理Tdi Connect模块
VOID CleanTdiConText();
//从List中申请内存
PDEVBUFFER TdiPacketAllocate(int lens);
//释放内存
void TdiPacketFree(PDEVBUFFER packet);
//获取存储数据信息
PDEVDATA GetTdiCtx();
//释放Tdi
VOID FreeTdi(_In_ PDRIVER_OBJECT pDriverObject);

//转换地址
ULONG ntohl(ULONG netlong);
unsigned short ntohs(unsigned short netshort);

//获取旧的obj指针
PDEVICE_OBJECT TdiGetOriginalObj(_In_ PDEVICE_OBJECT pDeviceObject, LPWCH pProtocolName);

//设置数据List
BOOL SetTdiHeadList(PTDILISTDATA pTdiListData, MonitorTypeSocket_EM netWorkType);
BOOL AddTdiConText(PDEVICE_OBJECT pDeviceObject, PFILE_OBJECT pFileObject);

//查找ConText数据
PTDILISTDATA FindTdiConText(PFILE_OBJECT pFileObj, BOOL isAssociate);
//删除一条ConText数据
BOOL DeleteTdiConText(PFILE_OBJECT deleteFileObj, BOOL isAssociate);

//检查数据量
VOID CheckTdiDataNum();
//打印所有数据
VOID PrintTdiData();
