#include "tdi.h"
#include "public.h"
#include "policy.h"

//=======================WINXP TDI（NDIS），其它系统不使用此过滤框架========================================

static PDEVICE_OBJECT g_ndisTcpFltobj = NULL;
static PDEVICE_OBJECT g_ndisUdpFltobj = NULL;
static PDEVICE_OBJECT g_ndisIpFltobj = NULL;

static PDEVICE_OBJECT g_ndisTcpOriginal = NULL;
static PDEVICE_OBJECT g_ndisUdpOriginal = NULL;
static PDEVICE_OBJECT g_ndisIpOriginal = NULL;

//Tdi Connect数据
static LIST_ENTRY g_tdiContextList;
static KSPIN_LOCK g_tdiContextLock;
static NPAGED_LOOKASIDE_LIST    g_tdiContextLookList;

//申请内存的List
static NPAGED_LOOKASIDE_LIST g_tdiList;
//Tdi数据
static DEVDATA g_tdiData;

#define NF_TAG_TDI 'IgTg'
#define NF_TAG_TDI_BUF 'IbTg'

//一条数据申请内存大小
#define TDI_ALLOCATESIZE sizeof(MonitorMsg)+sizeof(NETWORKINFO)
#define TDI_DATAMAXNUM LIST_MAX_SIZE/ TDI_ALLOCATESIZE

NTSTATUS TdiInit(_In_ PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	//初始化上下文相关
	sl_init(&g_tdiContextLock);
	InitializeListHead(&g_tdiContextList);

	ExInitializeNPagedLookasideList(
		&g_tdiContextLookList,
		NULL,
		NULL,
		0,
		sizeof(TDILISTDATA),
		NF_TAG_LIST,
		0
	);

	//初始化返回数据相关
	sl_init(&g_tdiData.lock);
	InitializeListHead(&g_tdiData.pending);
	ExInitializeNPagedLookasideList(
		&g_tdiList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	status = TdiAttachDevice(pDriverObject, &g_ndisTcpFltobj, &g_ndisTcpOriginal, L"\\Device\\Tcp");
	if (!NT_SUCCESS(status)) 
	{ 
		KdPrint(("%s:%d(%s) [Tdi]NdisAttachDevice(Tcp) error:%p\n", __FILE__, __LINE__, __FUNCTION__,status));
		goto FINAL;
	}

	status = TdiAttachDevice(pDriverObject, &g_ndisUdpFltobj, &g_ndisUdpOriginal, L"\\Device\\Udp");
	if (!NT_SUCCESS(status))
	{ 
		KdPrint(("%s:%d(%s) [Tdi]NdisAttachDevice(Udp) error:%p\n", __FILE__, __LINE__, __FUNCTION__,status));
		goto FINAL;
	}

	status = TdiAttachDevice(pDriverObject, &g_ndisIpFltobj, &g_ndisIpOriginal, L"\\Device\\RawIp");
	if (!NT_SUCCESS(status))
	{ 
		KdPrint(("%s:%d(%s) [Tdi]NdisAttachDevice(RawIp) error:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		goto FINAL;
	}

	KdPrint(("%s:%d(%s) [Tdi]NdisInit success\n", __FILE__, __LINE__, __FUNCTION__ ));

FINAL:
	if (!NT_SUCCESS(status))
	{
		FreeTdi(pDriverObject);
	}

	return status;
}


//绑定设备 TDI
NTSTATUS TdiAttachDevice(_In_ PDRIVER_OBJECT DriverObject, _Out_ PDEVICE_OBJECT *fltobj, _Out_ PDEVICE_OBJECT *oldobj, _In_ wchar_t *devname)
{
	NTSTATUS status;
	UNICODE_STRING str;

	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, TRUE, fltobj);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [Tdi]IoCreateDevice(%S) error:%p\n", __FILE__, __LINE__, __FUNCTION__ ,devname, status));

		return status;
	}

	//将设备名初始化为Unicode字符串
	RtlInitUnicodeString(&str, devname);

	//绑定设备
	status = IoAttachDevice(*fltobj, &str, oldobj);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [Tdi]IoAttachDevice(%S) error:%p\n", __FILE__, __LINE__, __FUNCTION__, devname, status));

		return status;
	}

	//设置设备IO方式为直接IO
	(*fltobj)->Flags |= DO_DIRECT_IO;
	
	//(*fltobj)->StackSize = (*oldobj)->StackSize + 1;
	//// XXX Flags &= ~DO_DEVICE_INITIALIZING;
	//(*fltobj)->Flags |= (*oldobj)->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE | DO_POWER_INRUSH) & ~DO_DEVICE_INITIALIZING;
	//(*fltobj)->DeviceType = (*oldobj)->DeviceType;
	//(*fltobj)->Characteristics = (*oldobj)->Characteristics;

	KdPrint(("%s:%d(%s) [Tdi]IoCreateDevice(%S)fltobj:0x%x,oldobj:0x%x\n", __FILE__, __LINE__, __FUNCTION__, 
		devname,*fltobj,*oldobj));

	return STATUS_SUCCESS;
}

//判断是否是Tdi
BOOL IsTdiObject(_In_ PDEVICE_OBJECT pDeviceObject)
{
	if (pDeviceObject == g_ndisTcpFltobj || pDeviceObject == g_ndisUdpFltobj ||
		pDeviceObject == g_ndisIpFltobj)
		return TRUE;

	return FALSE;
}

//总体的分发函数
NTSTATUS TdiDeviceDispatch(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION irpSp;
	irpSp = IoGetCurrentIrpStackLocation(pIrp);

	COMPLETION completion;
	RtlZeroMemory(&completion, sizeof(completion));

	switch (irpSp->MajorFunction)
	{
		//创建请求
	case IRP_MJ_CREATE:
	{
		int result = TdiCreate(pDeviceObject, pIrp, &completion);
		status = TdiDispatchComplete(pDeviceObject, pIrp, FILTER_ALLOW,
			completion.routine, completion.context);
		break;
	}
		//设备控制请求
	//case IRP_MJ_DEVICE_CONTROL:
	//	break;
		//内部设备控制请求
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	{
		int result = TdiInternal(pIrp, irpSp, &completion);
		status = TdiDispatchComplete(pDeviceObject, pIrp, FILTER_ALLOW,
			completion.routine, completion.context);
		break;
	}
	case IRP_MJ_CLEANUP:
		DeleteTdiConText(irpSp->FileObject,FALSE);
		status = TdiDispatchComplete(pDeviceObject, pIrp, FILTER_ALLOW,
			completion.routine, completion.context);
		break;
	default:
		status = TdiDispatchComplete(pDeviceObject, pIrp, FILTER_ALLOW,
			completion.routine, completion.context);
		break;
	}

	return status;
}

//消息处理完成函数
NTSTATUS TdiDispatchComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ int filter, _In_ PIO_COMPLETION_ROUTINE cr, _In_ PVOID context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(pIrp);
	NTSTATUS status;

	if (filter == FILTER_DENY) 
	{
		if (NT_SUCCESS(pIrp->IoStatus.Status))
		{
			status = pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
		}
		else 
		{
			status = pIrp->IoStatus.Status;
		}

		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	else if (filter == FILTER_ALLOW)
	{
		PDEVICE_OBJECT oldDevobj = TdiGetOriginalObj(pDeviceObject,NULL);

		if (oldDevobj == NULL)
		{
			status = pIrp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);

			return status;
		}

		if (cr == NULL || pIrp->CurrentLocation <= 1)
		{
			IoSkipCurrentIrpStackLocation(pIrp);

			if (cr != NULL) 
			{
				// save old completion routine and context
				PTDI_SKIP_CTX ctx = (PTDI_SKIP_CTX)ExAllocatePoolWithTag(NonPagedPool, sizeof(ctx), NF_TAG_TDI); 
				if (ctx == NULL) 
				{
					KdPrint(("%s:%d(%s) [Tdi]ExAllocatePoolWithTag error\n", __FILE__, __LINE__, __FUNCTION__));

					status = pIrp->IoStatus.Status = STATUS_SUCCESS;
					IoCompleteRequest(pIrp, IO_NO_INCREMENT);

					return status;
				}

				ctx->old_cr = irps->CompletionRoutine;
				ctx->old_context = irps->Context;
				ctx->new_cr = cr;
				ctx->new_context = context;
				ctx->fileobj = irps->FileObject;
				ctx->new_devobj = pDeviceObject;

				ctx->old_control = irps->Control;

				IoSetCompletionRoutine(pIrp, TdiSkipComplete, ctx, TRUE, TRUE, TRUE);
			}

		}
		else 
		{
			PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(pIrp),
				next_irps = IoGetNextIrpStackLocation(pIrp);

			memcpy(next_irps, irps, sizeof(*irps));

			if (cr != NULL) 
			{
				IoSetCompletionRoutine(pIrp, cr, context, TRUE, TRUE, TRUE);
			}
			else
			{
				IoSetCompletionRoutine(pIrp, TdiGenericComplete, NULL, TRUE, TRUE, TRUE);
			}
				
		}
		
		status = IoCallDriver(oldDevobj, pIrp);
	}
	else 
	{	
		status = pIrp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}

	return status;
}

//最终回调结束函数
NTSTATUS TdiGenericComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context)
{
	if (pIrp->PendingReturned)
	{
		IoMarkIrpPending(pIrp);
	}

	return STATUS_SUCCESS;
}

//过滤处理函数
NTSTATUS TdiSkipComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context)
{
	TDI_SKIP_CTX *ctx = (TDI_SKIP_CTX *)Context;
	NTSTATUS status;
	PIO_STACK_LOCATION irps;

	if (pIrp->IoStatus.Status != STATUS_SUCCESS)
		KdPrint(("%s:%d(%s) [Tdi]TdiSkipComplete Irp->IoStatus error:%p\n", __FILE__, __LINE__, __FUNCTION__, pIrp->IoStatus.Status));

	pIrp->CurrentLocation--;
	pIrp->Tail.Overlay.CurrentStackLocation--;

	irps = IoGetCurrentIrpStackLocation(pIrp);

	pDeviceObject = irps->DeviceObject;

	if (ctx->new_cr != NULL) 
	{
		irps->FileObject = ctx->fileobj;
		irps->DeviceObject = ctx->new_devobj;

		status = ctx->new_cr(ctx->new_devobj, pIrp, ctx->new_context);
	}
	else
		status = STATUS_SUCCESS;

	irps->CompletionRoutine = ctx->old_cr;
	irps->Context = ctx->old_context;
	irps->Control = ctx->old_control;

	irps->DeviceObject = pDeviceObject;

	pIrp->CurrentLocation++;
	pIrp->Tail.Overlay.CurrentStackLocation++;

	if (ctx->old_cr != NULL) 
	{
		if (status != STATUS_MORE_PROCESSING_REQUIRED) 
		{
			BOOLEAN b_call = FALSE;

			if (pIrp->Cancel)
			{
				if (ctx->old_control & SL_INVOKE_ON_CANCEL)
					b_call = TRUE;
			}
			else 
			{
				if (pIrp->IoStatus.Status >= STATUS_SUCCESS)
				{
					if (ctx->old_control & SL_INVOKE_ON_SUCCESS)
						b_call = TRUE;
				}
				else 
				{
					if (ctx->old_control & SL_INVOKE_ON_ERROR)
						b_call = TRUE;
				}
			}

			if (b_call)
				status = ctx->old_cr(pDeviceObject, pIrp, ctx->old_context);

		}
		else 
		{
			irps->Control = ctx->old_control;
		}
	}

	if (ctx)
	{
		ExFreePoolWithTag(ctx, NF_TAG_TDI);
		ctx = NULL;
	}

	return status;
}

//IRP_MJ_CREATE
int TdiCreate(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _Out_ PCOMPLETION pCompletion)
{
	PFILE_FULL_EA_INFORMATION ea = (PFILE_FULL_EA_INFORMATION)pIrp->AssociatedIrp.SystemBuffer;
	if (ea == NULL)
		return FILTER_DENY;

	PDEVICE_OBJECT devobj = TdiGetOriginalObj(pDeviceObject, NULL);
	if (devobj == NULL)
		return FILTER_DENY;

	PIO_STACK_LOCATION irpSp;
	irpSp = IoGetCurrentIrpStackLocation(pIrp);
	
	//传输层地址
	if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH && 
		RtlCompareMemory(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == TDI_TRANSPORT_ADDRESS_LENGTH)
	{
		if (FindTdiConText(irpSp->FileObject,FALSE) == NULL && !AddTdiConText(irpSp->DeviceObject, irpSp->FileObject))
		{
			return FILTER_DENY;
		}

		//创建一个空的irp
		PIRP query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, devobj, irpSp->FileObject, NULL, NULL);
		if (query_irp == NULL)
		{
			return FILTER_DENY;
		}	
		
		//指定一个完成函数
		pCompletion->routine = TdiCreateComplete;
		//把分配的irp记录
		pCompletion->context = query_irp;

	}
	//终端生成
	else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&
		RtlCompareMemory(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == TDI_CONNECTION_CONTEXT_LENGTH)
	{
		CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT*)(ea->EaName + ea->EaNameLength + 1);

		if (FindTdiConText(irpSp->FileObject, FALSE) == NULL && !AddTdiConText(irpSp->DeviceObject, irpSp->FileObject))
		{
			return FILTER_DENY;
		}
	}

	return FILTER_ALLOW;
}

//IRP_MJ_CREATE完成函数
NTSTATUS TdiCreateComplete(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context)
{
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(pIrp);
	PIRP query_irp = NULL;

	PTDI_CREATE_ADDROBJ2_CTX ctx = NULL;
	PMDL mdl = NULL;
	PDEVICE_OBJECT devobj = NULL;
	if (Context == NULL || pIrp == NULL)
	{
		goto FINAL;
	}

	query_irp = (PIRP)Context;
	if (!NT_SUCCESS(pIrp->IoStatus.Status))
	{
		status = pIrp->IoStatus.Status;
		goto FINAL;
	}

	ctx = (PTDI_CREATE_ADDROBJ2_CTX)ExAllocatePoolWithTag(NonPagedPool, sizeof(TDI_CREATE_ADDROBJ2_CTX), NF_TAG_TDI);
	if (ctx == NULL)
	{
		goto FINAL;
	}
	ctx->tai = (PTDI_ADDRESS_INFO)ExAllocatePoolWithTag(NonPagedPool, TDI_ADDRESS_INFO_MAX, NF_TAG_TDI);
	if (ctx->tai == NULL)
	{
		goto FINAL;
	}

	ctx->fileobj = irps->FileObject;

	mdl = IoAllocateMdl(ctx->tai, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL)
	{
		goto FINAL;
	}
	MmBuildMdlForNonPagedPool(mdl);

	devobj = TdiGetOriginalObj(pDeviceObject,NULL);
	if (devobj == NULL)
	{
		goto FINAL;
	}

	TdiBuildQueryInformation(query_irp, devobj, irps->FileObject,
		TdiCreateComplete2, ctx, TDI_QUERY_ADDRESS_INFO, mdl);
	status = IoCallDriver(devobj, query_irp);
	query_irp = NULL;
	mdl = NULL;
	ctx = NULL;

	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [Tdi]TdiCreateComplete error:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		goto FINAL;
	}

	status = STATUS_SUCCESS;

FINAL:
	if (mdl)
	{
		IoFreeMdl(mdl);
		mdl = NULL;
	}

	if (ctx)
	{
		if (ctx->tai)
		{
			ExFreePoolWithTag(ctx->tai, NF_TAG_TDI);
			ctx->tai = NULL;
		}
		ExFreePoolWithTag(ctx, NF_TAG_TDI);
		ctx = NULL;
	}

	if (query_irp)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);

	pIrp->IoStatus.Status = STATUS_SUCCESS;

	return TdiGenericComplete(pDeviceObject, pIrp, Context);
}

//创建行为处理函数（获取端口地址）
NTSTATUS TdiCreateComplete2(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Context)
{
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	PTDI_CREATE_ADDROBJ2_CTX ctx = NULL;
	PTA_ADDRESS addr = NULL;
	PTDILISTDATA pTdiListData = NULL;
	KLOCK_QUEUE_HANDLE lh;

	if (Context == NULL || !GetTypeConfig(MT_SocketCreate))
		goto FINAL;

	ctx = (TDI_CREATE_ADDROBJ2_CTX *)Context;
	if (ctx->tai == NULL)
		goto FINAL;
	addr = ctx->tai->Address.Address;
	if (addr == NULL)
		goto FINAL;

	pTdiListData = FindTdiConText(ctx->fileobj, FALSE);
	if (pTdiListData == NULL)
		goto FINAL;

	sl_lock(&g_tdiContextLock,&lh);
	pTdiListData->localIp = ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr);
	pTdiListData->localPort = ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port);

	SetTdiHeadList(pTdiListData, MT_SocketCreate);
	sl_unlock(&lh);

	//存储address
	//KdPrint(("[创建端口 %S]本地地址: %u.%u.%u.%u:%u,进程id:%d,线程id:%d,进程名:%s,进程路径:%S,进程创建时间:%d\n",
	//	pTdiData->protocolName,
	//	(pTdiData->localIp >> 24) & 0xFF, (pTdiData->localIp >> 16) & 0xFF, (pTdiData->localIp >> 8) & 0xFF, pTdiData->localIp & 0xFF,
	//	pTdiData->localPort,
	//	pTdiMsg->common.pid, pTdiData->threadId, pTdiMsg->common.comm, pTdiMsg->common.exe, pTdiData->createTime));


	status = STATUS_SUCCESS;
FINAL:
	if (pIrp->MdlAddress != NULL) 
	{
		IoFreeMdl(pIrp->MdlAddress);
		pIrp->MdlAddress = NULL;
	}

	if (ctx)
	{
		if (ctx->tai)
		{
			ExFreePoolWithTag(ctx->tai, NF_TAG_TDI);
			ctx->tai = NULL;
		}
		ExFreePoolWithTag(ctx, NF_TAG_TDI);
		ctx = NULL;
	}

	return status;
}

//处理数据传输消息
int TdiInternal(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	int result = FILTER_ALLOW;
	switch (pIrps->MinorFunction)
	{
		//关联地址对象和连接对象（IRP_MJ_CREATE中的两个），一般只有tcp有
	case TDI_ASSOCIATE_ADDRESS:
		result = TdiAssociateAddress(pIrp, pIrps, pCompletion);
		break;
	case TDI_CONNECT:
		result = TdiConnect(pIrp, pIrps, pCompletion);
		break;
	case TDI_SEND_DATAGRAM:
	case TDI_SEND:
		result = TdiSend(pIrp, pIrps, pCompletion);
		break;
		//udp
	//case TDI_SEND_DATAGRAM:
	//	result = TdiSendDataGram(pIrp, pIrps, pCompletion);
	//	break;
		//tcp
	case TDI_RECEIVE_DATAGRAM:
	case TDI_RECEIVE:
		result = TdiReceive(pIrp, pIrps, pCompletion);
		break;
		//udp
	//case TDI_RECEIVE_DATAGRAM:
	//	result = TdiReceiveDataGram(pIrp, pIrps, pCompletion);
	//	break;
	case TDI_DISCONNECT:
		result = TdiDisConnect(pIrp, pIrps, pCompletion);
		break;
	}

	return result;
}

//TDI_ASSOCIATE_ADDRESS	端口绑定
int TdiAssociateAddress(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	int result = FILTER_DENY;
	NTSTATUS status;

	HANDLE addr_handle = NULL;
	PFILE_OBJECT addrobj = NULL;
	PTDILISTDATA pTdiListData = NULL;
	KLOCK_QUEUE_HANDLE lh;

	if (!GetTypeConfig(MT_SocketBind))
		goto FINAL;

	addr_handle = ((TDI_REQUEST_KERNEL_ASSOCIATE *)(&pIrps->Parameters))->AddressHandle;
	status = ObReferenceObjectByHandle(addr_handle, GENERIC_READ, NULL, KernelMode, &addrobj, NULL);
	if (status != STATUS_SUCCESS) 
	{
		goto FINAL;
	}

	pTdiListData = FindTdiConText(addrobj, FALSE);
	if (pTdiListData == NULL)
		goto FINAL;

	sl_lock(&g_tdiContextLock,&lh);
	pTdiListData->associateFileObj = pIrps->FileObject;

	SetTdiHeadList(pTdiListData, MT_SocketBind);
	sl_unlock(&lh);

	//存储address
	//KdPrint(("[绑定端口 %S]本地地址: %u.%u.%u.%u:%u,进程id:%d,线程id:%d,进程名:%s,进程路径:%S,进程创建时间:%d\n",
	//	pTdiData->protocolName,
	//	(pTdiData->localIp >> 24) & 0xFF, (pTdiData->localIp >> 16) & 0xFF, (pTdiData->localIp >> 8) & 0xFF, pTdiData->localIp & 0xFF,
	//	pTdiData->localPort,
	//	pTdiMsg->common.pid, pTdiData->threadId, pTdiMsg->common.comm, pTdiMsg->common.exe, pTdiData->createTime));

	result = FILTER_ALLOW;
FINAL:
	if (addrobj)
	{
		ObDereferenceObject(addrobj);
		addrobj = NULL;
	}
	
	return result;
}

//TDI_CONNECT
int TdiConnect(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	int result = FILTER_DENY;

	PTDI_REQUEST_KERNEL_CONNECT param = NULL;
	PTA_ADDRESS remote_addr = NULL;
	
	PTDILISTDATA pTdiListData = NULL;
	KLOCK_QUEUE_HANDLE lh;

	if (!GetTypeConfig(MT_SocketConnect))
		goto FINAL;

	param = (PTDI_REQUEST_KERNEL_CONNECT)(&pIrps->Parameters);
	if (param == NULL)
		goto FINAL;
	remote_addr = ((TRANSPORT_ADDRESS *)(param->RequestConnectionInformation->RemoteAddress))->Address;
	if (!remote_addr)
		goto FINAL;

	//TCP
	pTdiListData = FindTdiConText(pIrps->FileObject, TRUE);
	if (pTdiListData == NULL)
	{
		//UDP
		pTdiListData = FindTdiConText(pIrps->FileObject, FALSE);
		if (pTdiListData == NULL)
		{
			goto FINAL;
		}
	}

	sl_lock(&g_tdiContextLock, &lh);
	pTdiListData->remoteIP = ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr);
	pTdiListData->remotePort = ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port);

	SetTdiHeadList(pTdiListData, MT_SocketConnect);
	sl_unlock(&lh);

	//存储address
	//KdPrint(("[网络连接 %S]本地地址: %u.%u.%u.%u:%u,目的地址: %u.%u.%u.%u:%u,进程id:%d,线程id:%d,进程名:%s,进程路径:%S,进程创建时间:%d\n",
	//	pTdiData->protocolName,
	//	(pTdiData->localIp >> 24) & 0xFF, (pTdiData->localIp >> 16) & 0xFF, (pTdiData->localIp >> 8) & 0xFF, pTdiData->localIp & 0xFF,
	//	pTdiData->localPort,
	//	(pTdiData->remoteIP >> 24) & 0xFF, (pTdiData->remoteIP >> 16) & 0xFF, (pTdiData->remoteIP >> 8) & 0xFF, pTdiData->remoteIP & 0xFF,
	//	pTdiData->remotePort,
	//	pTdiMsg->common.pid, pTdiData->threadId, pTdiMsg->common.comm, pTdiMsg->common.exe, pTdiData->createTime));

	result = FILTER_ALLOW;
FINAL:
	if(result != FILTER_ALLOW)
		pIrp->IoStatus.Status = STATUS_SUCCESS;

	return result;
}

//TDI_SEND
int TdiSend(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	PTDI_REQUEST_KERNEL_CONNECT param = NULL;
	PTA_ADDRESS remote_addr = NULL;

	PTDILISTDATA pTdiListData = NULL;
	KLOCK_QUEUE_HANDLE lh;

	if (!GetTypeConfig(MT_SocketSend))
		goto FINAL;

	//TCP
	pTdiListData = FindTdiConText(pIrps->FileObject, TRUE);
	if (pTdiListData == NULL)
	{
		//UDP
		pTdiListData = FindTdiConText(pIrps->FileObject, FALSE);
		if (pTdiListData == NULL)
		{
			goto FINAL;
		}
	}		

	sl_lock(&g_tdiContextLock, &lh);
	SetTdiHeadList(pTdiListData, MT_SocketSend);
	sl_unlock(&lh);

	//SetTdiHeadList(pTdiMsg);

	//存储address
	//KdPrint(("[数据发送 %S]本地地址: %u.%u.%u.%u:%u,目的地址: %u.%u.%u.%u:%u,进程id:%d,线程id:%d,进程名:%s,进程路径:%S,进程创建时间:%d\n",
	//	pTdiData->protocolName,
	//	(pTdiData->localIp >> 24) & 0xFF, (pTdiData->localIp >> 16) & 0xFF, (pTdiData->localIp >> 8) & 0xFF, pTdiData->localIp & 0xFF,
	//	pTdiData->localPort,
	//	(pTdiData->remoteIP >> 24) & 0xFF, (pTdiData->remoteIP >> 16) & 0xFF, (pTdiData->remoteIP >> 8) & 0xFF, pTdiData->remoteIP & 0xFF,
	//	pTdiData->remotePort,
	//	pTdiMsg->common.pid, pTdiData->threadId, pTdiMsg->common.comm, pTdiMsg->common.exe, pTdiData->createTime));


FINAL:

	return FILTER_ALLOW;
}

//TDI_SEND_DATAGRAM
int TdiSendDataGram(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	KdPrint(("[Tdi]数据发送(UDP)\n"));
	int result = FILTER_DENY;


	result = FILTER_ALLOW;
//FINAL:

	return result;
}

NTSTATUS TdiReceiveComplete(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp, IN PVOID Context)
{
	PTDILISTDATA pTdiListData = NULL;
	KLOCK_QUEUE_HANDLE lh;
	PIO_STACK_LOCATION irps = NULL;

	if (!GetTypeConfig(MT_SocketRecv))
		goto FINAL;

	irps = IoGetCurrentIrpStackLocation(pIrp);
	if (irps == NULL)
		goto FINAL;

	//TCP
	pTdiListData = FindTdiConText(irps->FileObject, TRUE);
	if (pTdiListData == NULL)
	{
		//UDP
		pTdiListData = FindTdiConText(irps->FileObject, FALSE);
		if (pTdiListData == NULL)
		{
			goto FINAL;
		}
	}

	sl_lock(&g_tdiContextLock, &lh);
	SetTdiHeadList(pTdiListData, MT_SocketRecv);
	sl_unlock(&lh);

	//存储address
	//KdPrint(("[数据接收 %S]本地地址: %u.%u.%u.%u:%u,目的地址: %u.%u.%u.%u:%u,进程id:%d,线程id:%d,进程名:%s,进程路径:%S,进程创建时间:%d\n",
	//	pTdiData->protocolName,
	//	(pTdiData->localIp >> 24) & 0xFF, (pTdiData->localIp >> 16) & 0xFF, (pTdiData->localIp >> 8) & 0xFF, pTdiData->localIp & 0xFF,
	//	pTdiData->localPort,
	//	(pTdiData->remoteIP >> 24) & 0xFF, (pTdiData->remoteIP >> 16) & 0xFF, (pTdiData->remoteIP >> 8) & 0xFF, pTdiData->remoteIP & 0xFF,
	//	pTdiData->remotePort,
	//	pTdiMsg->common.pid, pTdiData->threadId, pTdiMsg->common.comm, pTdiMsg->common.exe, pTdiData->createTime));


FINAL:

	return TdiGenericComplete(DeviceObject, pIrp, Context);
}

//TDI_RECEIVE
int TdiReceive(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	TDI_REQUEST_KERNEL_RECEIVE *param = (TDI_REQUEST_KERNEL_RECEIVE *)(&pIrps->Parameters);

	if (!(param->ReceiveFlags & TDI_RECEIVE_PEEK)) 
	{
		pCompletion->routine = TdiReceiveComplete;
	}

	return FILTER_ALLOW;
}

//TDI_RECEIVE_DATAGRAM
int TdiReceiveDataGram(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	KdPrint(("[Tdi]数据接收(UDP)\n"));
	int result = FILTER_DENY;


	result = FILTER_ALLOW;
//FINAL:

	return result;
}

//TDI_DISCONNECT
int TdiDisConnect(_In_ PIRP pIrp, _In_ PIO_STACK_LOCATION pIrps, _Out_ PCOMPLETION pCompletion)
{
	int result = FILTER_DENY;

	PTDILISTDATA pTdiListData = NULL;
	KLOCK_QUEUE_HANDLE lh;
	PFILE_OBJECT deleteFileObj = NULL;
	PIO_STACK_LOCATION irps = NULL;
	BOOL isTcp = TRUE;

	if (!GetTypeConfig(MT_SocketClose))
		goto FINAL;

	irps = IoGetCurrentIrpStackLocation(pIrp);
	if (irps == NULL)
		goto FINAL;

	//TCP
	pTdiListData = FindTdiConText(irps->FileObject, TRUE);
	if (pTdiListData == NULL)
	{
		isTcp = FALSE;
		//UDP
		pTdiListData = FindTdiConText(irps->FileObject, FALSE);
		if (pTdiListData == NULL)
		{
			goto FINAL;
		}
	}

	sl_lock(&g_tdiContextLock, &lh);
	SetTdiHeadList(pTdiListData, MT_SocketClose);
	sl_unlock(&lh);

	//存储address
	//KdPrint(("[网络关闭 %S]本地地址: %u.%u.%u.%u:%u,目的地址: %u.%u.%u.%u:%u,进程id:%d,线程id:%d,进程名:%s,进程路径:%S,进程创建时间:%d\n",
	//	pTdiData->protocolName,
	//	(pTdiData->localIp >> 24) & 0xFF, (pTdiData->localIp >> 16) & 0xFF, (pTdiData->localIp >> 8) & 0xFF, pTdiData->localIp & 0xFF,
	//	pTdiData->localPort,
	//	(pTdiData->remoteIP >> 24) & 0xFF, (pTdiData->remoteIP >> 16) & 0xFF, (pTdiData->remoteIP >> 8) & 0xFF, pTdiData->remoteIP & 0xFF,
	//	pTdiData->remotePort,
	//	pTdiMsg->common.pid, pTdiData->threadId, pTdiMsg->common.comm, pTdiMsg->common.exe, pTdiData->createTime));

	//删除保存的context数据
	DeleteTdiConText(irps->FileObject, isTcp);
	
	result = FILTER_ALLOW;
FINAL:

	return result;
}

//获取Tdi对应的设备句柄
PDEVICE_OBJECT TdiGetOriginalObj(PDEVICE_OBJECT pDeviceObject,LPWCH pProtocolName)
{
	PDEVICE_OBJECT result = NULL;

	if (pDeviceObject == g_ndisTcpFltobj)
	{
		result = g_ndisTcpOriginal;
		if (pProtocolName)
		{
			RtlCopyMemory(pProtocolName, L"TCP", sizeof(L"TCP"));
		}
	}
	else if (pDeviceObject == g_ndisUdpFltobj)
	{
		result = g_ndisUdpOriginal;
		if (pProtocolName)
		{
			RtlCopyMemory(pProtocolName, L"UDP", sizeof(L"UDP"));
		}
	}
	else if (pDeviceObject == g_ndisIpFltobj)
	{
		result = g_ndisIpOriginal;
		if (pProtocolName)
		{
			RtlCopyMemory(pProtocolName, L"IP", sizeof(L"IP"));
		}
	}

	return result;
}

//设置数据List
BOOL SetTdiHeadList(PTDILISTDATA pTdiListData, MonitorTypeSocket_EM netWorkType)
{
	PMonitorMsg pTdiMsg = NULL;
	PNETWORKINFO pTdiData = NULL;
	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pInfo = NULL;

	if (pTdiListData == NULL)
		goto FINAL;

	pTdiMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, TDI_ALLOCATESIZE, NF_TAG_TDI);
	if (pTdiMsg == NULL)
		goto FINAL;

	RtlZeroMemory(pTdiMsg, TDI_ALLOCATESIZE);

	pTdiData = (PNETWORKINFO)pTdiMsg->data;
	if (pTdiData == NULL)
		goto FINAL;

	pTdiMsg->common.type = Monitor_Socket;

	pTdiData->localIp = pTdiListData->localIp;
	pTdiData->localPort = pTdiListData->localPort;

	pTdiData->remoteIP = pTdiListData->remoteIP;
	pTdiData->remotePort = pTdiListData->remotePort;

	pTdiMsg->common.pid = pTdiListData->pid;
	pTdiData->threadId = pTdiListData->threadId;
	pTdiMsg->common.ppid = pTdiListData->pPid;
	pTdiData->createTime = pTdiListData->createTime;

	RtlCopyMemory(pTdiMsg->common.comm, pTdiListData->processName, sizeof(pTdiMsg->common.comm));
	RtlCopyMemory(pTdiMsg->common.exe, pTdiListData->processPath, sizeof(pTdiMsg->common.exe));
	RtlCopyMemory(pTdiData->protocolName, pTdiListData->protocolName, sizeof(pTdiData->protocolName));

	pTdiData->type = netWorkType;
	GetCurrentTimeString(&pTdiMsg->common.time);

	pInfo = (PDEVBUFFER)TdiPacketAllocate(TDI_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [TDI]TdiPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pTdiMsg, TDI_ALLOCATESIZE);

	//获取数据量
	CheckTdiDataNum();

	sl_lock(&g_tdiData.lock, &lh);
	InsertHeadList(&g_tdiData.pending, &pInfo->pEntry);

	g_tdiData.dataSize++;
	sl_unlock(&lh);

	PushInfo(Monitor_Socket);

FINAL:
	if (pTdiMsg)
	{
		ExFreePoolWithTag(pTdiMsg, NF_TAG_TDI);
		pTdiMsg = NULL;
	}

	return TRUE;
}

BOOL AddTdiConText(PDEVICE_OBJECT pDeviceObject, PFILE_OBJECT pFileObject)
{
	if (pDeviceObject == NULL || pFileObject == NULL)
		return FALSE;

	PTDILISTDATA pTdiConnectData = (PTDILISTDATA)ExAllocateFromNPagedLookasideList(&g_tdiContextLookList); 
	if (!pTdiConnectData)
		return FALSE;
	RtlZeroMemory(pTdiConnectData, sizeof(TDILISTDATA));

	pTdiConnectData->fileobj = pFileObject;

	TdiGetOriginalObj(pDeviceObject, pTdiConnectData->protocolName);

	pTdiConnectData->pid = (DWORD)PsGetCurrentProcessId();
	pTdiConnectData->threadId = (DWORD)PsGetCurrentThreadId();
	GetProcessNameByPID(pTdiConnectData->pid, pTdiConnectData->processName, sizeof(pTdiConnectData->processName), &pTdiConnectData->pPid);
	GetProcessCreateTimeByPID(pTdiConnectData->pid, &pTdiConnectData->createTime);

	WCHARMAX processPath = { 0 };
	if (QueryProcessNamePath((DWORD)pTdiConnectData->pid, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pTdiConnectData->processPath, processPath, sizeof(processPath));
	}

	if (pTdiConnectData->processName[0] != '\0')
	{
		if (!IsAllowData(POLICY_EXE_LIST, pTdiConnectData->processName, FALSE))
		{
			return FALSE;
		}
	}
	else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pTdiConnectData->processPath, TRUE))
		{
			return FALSE;
		}
	}


	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_tdiContextLock,&lh);
	InsertHeadList(&g_tdiContextList, &pTdiConnectData->pending);
	sl_unlock(&lh);

	return TRUE;
}

//查找ConText数据
PTDILISTDATA FindTdiConText(PFILE_OBJECT pFileObj,BOOL isAssociate)
{
	PTDILISTDATA pTdiListData = NULL;

	if (!pFileObj)
		return pTdiListData;

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_tdiContextLock, &lh);
	PLIST_ENTRY pTdiListEntry = &g_tdiContextList;
	LIST_ENTRY* p = NULL;
	for (p = pTdiListEntry->Flink; p != pTdiListEntry; p = p->Flink)
	{
		PTDILISTDATA pTdiList = CONTAINING_RECORD(p, TDILISTDATA, pending);
		if (!pTdiList)
			continue;

		if (isAssociate)
		{
			if (pTdiList->associateFileObj == pFileObj)
			{
				pTdiListData = pTdiList;
				break;
			}
		}
		else
		{
			if (pTdiList->fileobj == pFileObj)
			{
				pTdiListData = pTdiList;
				break;
			}
		}
	}

	sl_unlock(&lh);

	return pTdiListData;
}

//删除一条ConText数据
BOOL DeleteTdiConText(PFILE_OBJECT deleteFileObj, BOOL isAssociate)
{
	if (deleteFileObj == NULL)
		return TRUE;

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_tdiContextLock, &lh);
	PLIST_ENTRY ptdiListEntry = &g_tdiContextList;
	LIST_ENTRY* p = NULL;
	for (p = ptdiListEntry->Flink; p != ptdiListEntry; p = p->Flink)
	{
		PTDILISTDATA pTdiList = CONTAINING_RECORD(p, TDILISTDATA, pending);
		if (!pTdiList)
			continue;

		if (isAssociate)
		{
			if (pTdiList->associateFileObj == deleteFileObj)
			{
				if (pTdiList->associateFileObj != pTdiList->fileobj)
				{
					sl_unlock(&lh);
					DeleteTdiConText(pTdiList->fileobj, FALSE);
					sl_lock(&g_tdiContextLock, &lh);

					sl_unlock(&lh);
					DeleteTdiConText(deleteFileObj, TRUE);
					sl_lock(&g_tdiContextLock, &lh);
				}
				else
				{
					RemoveEntryList(pTdiList);
					ExFreeToNPagedLookasideList(&g_tdiContextLookList, pTdiList);
					pTdiList = NULL;
				}
				break;
			}
		}
		else
		{
			if (pTdiList->fileobj == deleteFileObj)
			{
				RemoveEntryList(pTdiList);
				ExFreeToNPagedLookasideList(&g_tdiContextLookList, pTdiList);
				pTdiList = NULL;
				break;
			}
		}
	}

	sl_unlock(&lh);

	return TRUE;
}

//打印所有数据
VOID PrintTdiData()
{
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_tdiContextLock,&lh);
	PLIST_ENTRY pTdiListEntry = &g_tdiContextList;
	PLIST_ENTRY p = NULL;
	for (p = pTdiListEntry->Flink; p != pTdiListEntry; p = p->Flink)
	{
		PTDILISTDATA policyList = CONTAINING_RECORD(p, TDILISTDATA, pending);
		KdPrint(("本地ip;%u.%u.%u.%u:%u,目的ip:%u.%u.%u.%u.%u\n",
			(policyList->localIp>>24)&0xFF, (policyList->localIp>>16)&0xFF,(policyList->localIp>>8)&0xFF, policyList->localIp&0xFF,
			policyList->localPort,
			(policyList->remoteIP >> 24) & 0xFF, (policyList->remoteIP >> 16) & 0xFF, (policyList->remoteIP >> 8) & 0xFF, policyList->remoteIP & 0xFF,
			policyList->remotePort));
	}
	sl_unlock(&lh);
	
}

//清理Tdi模块
VOID CleanTdi()
{
	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_tdiData.lock, &lh);
		lock_status = 1;

		while (!IsListEmpty(&g_tdiData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_tdiData.pending);
			if (!pData)
				break;

			g_tdiData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			TdiPacketFree(pData);
			pData = NULL;
			sl_lock(&g_tdiData.lock, &lh);
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

//清理Tdi ConText模块
VOID CleanTdiConText()
{
	KLOCK_QUEUE_HANDLE lh;
	PTDILISTDATA pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_tdiContextLock, &lh);
		lock_status = 1;

		while (!IsListEmpty(&g_tdiContextList))
		{
			pData = (PTDILISTDATA)RemoveHeadList(&g_tdiContextList);
			if (!pData)
				break;

			sl_unlock(&lh);
			lock_status = 0;
			ExFreeToNPagedLookasideList(&g_tdiContextLookList, pData);
			pData = NULL;
			sl_lock(&g_tdiContextLock, &lh);
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


//释放Tdi
VOID FreeTdi(PDRIVER_OBJECT pDriverObject)
{
	if (g_ndisTcpFltobj)
	{
		CleanTdi();
		CleanTdiConText();
		ExDeleteNPagedLookasideList(&g_tdiList);
		ExDeleteNPagedLookasideList(&g_tdiContextLookList);
	}

	//卸载tcp
	if (g_ndisTcpOriginal != NULL)
	{
		IoDetachDevice(g_ndisTcpOriginal);
		g_ndisTcpOriginal = NULL;
	}
	if (g_ndisTcpFltobj != NULL)
	{
		IoDeleteDevice(g_ndisTcpFltobj);
		g_ndisTcpFltobj = NULL;
	}

	//卸载udp
	if (g_ndisUdpOriginal != NULL)
	{
		IoDetachDevice(g_ndisUdpOriginal);
		g_ndisUdpOriginal = NULL;
	}
	if (g_ndisUdpFltobj != NULL)
	{
		IoDeleteDevice(g_ndisUdpFltobj);
		g_ndisUdpFltobj = NULL;
	}

	//卸载ip
	if (g_ndisIpOriginal != NULL)
	{
		IoDetachDevice(g_ndisIpOriginal);
		g_ndisIpOriginal = NULL;
	}
	if (g_ndisIpFltobj != NULL)
	{
		IoDeleteDevice(g_ndisIpFltobj);
		g_ndisIpFltobj = NULL;
	}

	KdPrint(("%s:%d(%s) [Tdi]FreeNdis end\n", __FILE__, __LINE__, __FUNCTION__));
}

//从List中申请内存
PDEVBUFFER TdiPacketAllocate(int lens)
{
	PDEVBUFFER pTdibuf = NULL;
	if (lens <= 0)
		return pTdibuf;

	pTdibuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_tdiList);
	if (!pTdibuf)
		return pTdibuf;

	RtlZeroMemory(pTdibuf, sizeof(DEVBUFFER));

	pTdibuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_TDI_BUF);
	if (!pTdibuf->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_tdiList, pTdibuf);
		pTdibuf = NULL;
		return pTdibuf;
	}
	pTdibuf->dataLength = lens;
	RtlZeroMemory(pTdibuf->dataBuffer, lens);
	
	return pTdibuf;
}

//释放内存
void TdiPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;

	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_TDI_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_tdiList, packet);
}

//获取存储数据信息
PDEVDATA GetTdiCtx()
{
	return &g_tdiData;
}

//检查数据量
VOID CheckTdiDataNum()
{
	if (g_tdiData.dataSize > TDI_DATAMAXNUM)
	{
		CleanTdi();
	}
}



//===========================================================================================

ULONG ntohl(ULONG netlong)
{
	ULONG result = 0;
	((char *)&result)[0] = ((char *)&netlong)[3];
	((char *)&result)[1] = ((char *)&netlong)[2];
	((char *)&result)[2] = ((char *)&netlong)[1];
	((char *)&result)[3] = ((char *)&netlong)[0];
	return result;
}

unsigned short ntohs(unsigned short netshort)
{
	unsigned short result = 0;
	((char *)&result)[0] = ((char *)&netshort)[1];
	((char *)&result)[1] = ((char *)&netshort)[0];
	return result;
}
