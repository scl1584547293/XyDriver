#include "network.h"
#include "devctrl.h"
#include "policy.h"

PDRIVER_OBJECT  gDevObj = NULL;

//句柄
static HANDLE    gEngineHandle = 0;
//网络连接
static UINT32    gAleConnectCalloutId = 0;
//DNS解析
static UINT32    gAleDataCalloutId = 0;
//数据传输
static UINT32    gAleTransCalloutId = 0;
//创建端口
static UINT32    gAleCreatePortCalloutId = 0;
//绑定端口
static UINT32    gAleBindPortCalloutId = 0;
//关闭链接
static UINT32    gAleCloseCalloutId = 0;

//uuid
//连接网络
static GUID GUID_ALE_AUTH_CONNECT_CALLOUT_V4 = { 0, };
//DNS解析
static GUID GUID_ALE_AUTH_DATAGRAM_DATA_V4 = { 0, };
//数据传输
static GUID TL_OUTBOUND_TRANSPORT = { 0, };
//断开链接
static GUID GUID_ENDPOINT_CLOSURE = { 0, };
//创建端口
static GUID GUID_BIND_REDIRECT = { 0, };
//绑定端口
static GUID GUID_RESOURCE_ASSIGNMENTE = { 0, };

//锁
static KSPIN_LOCK g_flowContextListLock;
//上下文List
static LIST_ENTRY g_flowContextList;
#define		NF_TAG_NET			'NgTg'
#define NF_TAG_NET_BUF 'NbTg'

//一条数据申请内存大小
#define NETWORK_ALLOCATESIZE sizeof(MonitorMsg) + sizeof(NETWORKINFO)
#define NETWORK_DATAMAXNUM LIST_MAX_SIZE/NETWORK_ALLOCATESIZE

static BOOL g_IsClean = FALSE;

//申请内存List
static NPAGED_LOOKASIDE_LIST g_netWorkList;
//数据
static DEVDATA g_netWorkData;

//注册
NTSTATUS RegisterCalloutForLayer
(
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT UINT32* calloutId,
	OUT UINT64* filterId
)
{
	NTSTATUS        status = STATUS_SUCCESS;
	FWPS_CALLOUT    sCallout = { 0 };
	FWPM_FILTER     mFilter = { 0 };
	FWPM_FILTER_CONDITION mFilter_condition[1] = { 0 };
	FWPM_CALLOUT    mCallout = { 0 };
	FWPM_DISPLAY_DATA mDispData = { 0 };
	BOOL         bCalloutRegistered = FALSE;
	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteNotifyFn;
	sCallout.notifyFn = notifyFn;
	//要使用哪个设备对象注册
	status = FwpsCalloutRegister(gDevObj, &sCallout, calloutId);
	if (!NT_SUCCESS(status))
		goto exit;
	bCalloutRegistered = TRUE;
	mDispData.name = L"WFP TEST";
	mDispData.description = L"test network";
	//你感兴趣的内容
	mCallout.applicableLayer = *layerKey;
	//你感兴趣的内容的GUID
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;
	//if(GuidCmpare(FWPM_LAYER_STREAM_V4,*layerKey))
	//	mCallout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
	//添加回调函数
	status = FwpmCalloutAdd(gEngineHandle, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status))
		goto exit;
	mFilter.action.calloutKey = *calloutKey;
	//在callout里决定
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	mFilter.displayData.name = L"WFP ZrWorld";
	mFilter.displayData.description = L"ZrWorld NetWork";
	mFilter.layerKey = *layerKey;
	mFilter.numFilterConditions = 0;
	mFilter.filterCondition = mFilter_condition;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;
	//添加过滤器
	status = FwpmFilterAdd(gEngineHandle, &mFilter, NULL, NULL);
	if (!NT_SUCCESS(status))
		goto exit;
exit:
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [NetWork]RegisterCalloutForLayer err\n", __FILE__, __LINE__, __FUNCTION__));
		if (bCalloutRegistered)
		{
			FwpsCalloutUnregisterById(*calloutId);
		}
	}
	return status;
}

//初始化网络模块
NTSTATUS WallRegisterCallouts(PDRIVER_OBJECT  DevObj)
{
	//UNREFERENCED_PARAMETER(DevObj);

	gDevObj = DevObj;
	NTSTATUS    status = STATUS_SUCCESS;
	BOOL     bInTransaction = FALSE;
	BOOL     bEngineOpened = FALSE;

	InitializeListHead(&g_flowContextList);

	sl_init(&g_netWorkData.lock);
	InitializeListHead(&g_netWorkData.pending);
	//初始化锁
	sl_init(&g_flowContextListLock);

	ExInitializeNPagedLookasideList(
		&g_netWorkList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;

	FWPM_SESSION session = { 0 };
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	//开启WFP引擎
	status = FwpmEngineOpen(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bEngineOpened = TRUE;
	//确认过滤权限
	status = FwpmTransactionBegin(gEngineHandle, 0);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = TRUE;

	ExUuidCreate((GUID*)&GUID_ALE_AUTH_CONNECT_CALLOUT_V4);
	//注册回调函数
	//连接
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		&GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
		WallALEConnectClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleConnectCalloutId,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [NetWork]FWPM_LAYER_ALE_AUTH_CONNECT_V4 err\n", __FILE__, __LINE__, __FUNCTION__));
		goto exit;
	}

	//创建端口
	ExUuidCreate((GUID*)&GUID_BIND_REDIRECT);
	//注册回调函数
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_BIND_REDIRECT_V4,
		&GUID_BIND_REDIRECT,
		WallALECreatePortClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleCreatePortCalloutId,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [NetWork]FWPM_LAYER_ALE_AUTH_CONNECT_V4 err\n", __FILE__, __LINE__, __FUNCTION__));
		goto exit;
	}

	//绑定端口
	ExUuidCreate((GUID*)&GUID_RESOURCE_ASSIGNMENTE);
	//注册回调函数
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
		&GUID_RESOURCE_ASSIGNMENTE,
		WallALEBindPortClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleBindPortCalloutId,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [NetWork]FWPM_LAYER_ALE_AUTH_CONNECT_V4 err\n", __FILE__, __LINE__, __FUNCTION__));
		goto exit;
	}

	//断开连接
	ExUuidCreate((GUID*)&GUID_ENDPOINT_CLOSURE);
	//注册回调函数
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
		&GUID_ENDPOINT_CLOSURE,
		WallALECloseClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleCloseCalloutId,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [NetWork]FWPM_LAYER_ALE_AUTH_CONNECT_V4 err\n", __FILE__, __LINE__, __FUNCTION__));
		goto exit;
	}

	//传输数据
	ExUuidCreate((GUID*)&TL_OUTBOUND_TRANSPORT);
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_STREAM_V4,
		&TL_OUTBOUND_TRANSPORT,
		WallALELayerStreamClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleTransCalloutId,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCalloutForLayer-FWPM_LAYER_STREAM_V4 failed!\n"));
		goto exit;
	}

	//DNS
	//ExUuidCreate((GUID*)&GUID_ALE_AUTH_DATAGRAM_DATA_V4);
	//status = RegisterCalloutForLayer(
	//	&FWPM_LAYER_DATAGRAM_DATA_V4,
	//	&GUID_ALE_AUTH_DATAGRAM_DATA_V4,
	//	WallALEDnsClassify,
	//	WallNotifyFn,
	//	WallFlowDeleteFn,
	//	&gAleDataCalloutId,
	//	NULL);
	//if (!NT_SUCCESS(status))
	//{
	//	KdPrint(("%s:%d(%s) [NetWork]FWPM_LAYER_DATAGRAM_DATA_V4 err\n", __FILE__, __LINE__, __FUNCTION__));
	//	goto exit;
	//}


	//确认所有内容并提交，让回调函数正式发挥作用
	status = FwpmTransactionCommit(gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = FALSE;
exit:
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [NetWork]WallRegisterCallouts err\n", __FILE__, __LINE__, __FUNCTION__));
		if (bInTransaction)
		{
			FwpmTransactionAbort(gEngineHandle);
		}
		if (bEngineOpened)
		{
			FwpmEngineClose(gEngineHandle);
			gEngineHandle = 0;
		}
	}
	return status;
}

//清理网络模块
VOID CleanNetWork()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_netWorkData.lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_netWorkData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_netWorkData.pending);
			if (!pData)
				break;
			g_netWorkData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			NetWorkPacketFree(pData);
			pData = NULL;
			sl_lock(&g_netWorkData.lock, &lh);
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

//卸载网络模块
NTSTATUS WallUnRegisterCallouts()
{
	KdPrint(("%s:%d(%s) WallUnRegisterCallouts\n", __FILE__, __LINE__, __FUNCTION__));

	if (!g_IsClean)
		return STATUS_SUCCESS;

	CleanNetWork();
	ExDeleteNPagedLookasideList(&g_netWorkList);

	KLOCK_QUEUE_HANDLE lockHandle;
	sl_lock(&g_flowContextListLock, &lockHandle);

	while (!IsListEmpty(&g_flowContextList))
	{
		FLOW_DATA* flowContext;
		LIST_ENTRY* entry;
		NTSTATUS status;

		entry = RemoveHeadList(&g_flowContextList);
		if (!entry)
		{
			break;
		}

		//上下文
		flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);

		//防止最后卸载不干净使用的
		flowContext->deleting = TRUE;

		//KdPrint(("WallUnRegisterCallouts RemoveHeadList:%d\n", flowContext->flowHandle));
		if (gAleTransCalloutId &&(flowContext->ContextFlag & NF_CONTEXTFLAG_STREAM_ASSOCIATED) == NF_CONTEXTFLAG_STREAM_ASSOCIATED)
		{
			status = FwpsFlowRemoveContext(flowContext->flowHandle,
				FWPS_LAYER_STREAM_V4,
				gAleTransCalloutId);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("FwpsFlowRemoveContext FWPS_LAYER_STREAM_V4 error\n"));
			}
		}
		if (gAleDataCalloutId && (flowContext->ContextFlag & NF_CONTEXTFLAG_DATAGRAM_ASSOCIATED) == NF_CONTEXTFLAG_DATAGRAM_ASSOCIATED)
		{
			status = FwpsFlowRemoveContext(flowContext->flowHandle,
				FWPS_LAYER_DATAGRAM_DATA_V4,
				gAleDataCalloutId);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("FwpsFlowRemoveContext FWPS_LAYER_DATAGRAM_DATA_V4 error\n"));
			}
		}

		if ((flowContext->ContextFlag & NF_CONTEXTFLAG_CLOSUSER_ASSOCIATED) == NF_CONTEXTFLAG_CLOSUSER_ASSOCIATED)
		{
			status = FwpsFlowRemoveContext(flowContext->flowHandle,
				FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4,
				gAleCloseCalloutId);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("FwpsFlowRemoveContext FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 error\n"));
			}
		}

	}
	sl_unlock(&lockHandle);

	if (gAleCreatePortCalloutId)
	{
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleCreatePortCalloutId);
		FwpsCalloutUnregisterByKey(&GUID_BIND_REDIRECT);
		//清空CalloutId
		gAleCreatePortCalloutId = 0;
	}

	if (gAleBindPortCalloutId)
	{	
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleBindPortCalloutId);
		FwpsCalloutUnregisterByKey(&GUID_RESOURCE_ASSIGNMENTE);
		//清空CalloutId
		gAleBindPortCalloutId = 0;
	}

	if (gAleCloseCalloutId)
	{
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleCloseCalloutId);
		FwpsCalloutUnregisterByKey(&GUID_ENDPOINT_CLOSURE);
		//清空CalloutId
		gAleCloseCalloutId = 0;
	}

	if (gAleConnectCalloutId)
	{
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleConnectCalloutId);
		FwpsCalloutUnregisterByKey(&GUID_ALE_AUTH_CONNECT_CALLOUT_V4);

		//清空CalloutId
		gAleConnectCalloutId = 0;
	}

	if (gAleTransCalloutId)
	{
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleTransCalloutId);
		FwpsCalloutUnregisterByKey(&GUID_ALE_AUTH_DATAGRAM_DATA_V4);
		//清空CalloutId
		gAleTransCalloutId = 0;
	}


	if (gAleDataCalloutId)
	{
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleDataCalloutId);
		FwpsCalloutUnregisterByKey(&TL_OUTBOUND_TRANSPORT);
		//清空CalloutId
		gAleDataCalloutId = 0;
	}

	if (gEngineHandle != 0)
	{
		//关闭引擎
		FwpmEngineClose(gEngineHandle);
		gEngineHandle = 0;
	}

	return STATUS_SUCCESS;
}


/*
以下两个回调函数没啥用
*/
NTSTATUS NTAPI WallNotifyFn
(
	IN FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
	IN const GUID  *filterKey,
	IN FWPS_FILTER  *filter
)
{
	return STATUS_SUCCESS;
}

//释放上下文
VOID NTAPI ReleaseFlowContext(PFLOW_DATA flowData)
{
	if (0 == flowData)
	{
		return;
	}

	//LONG refCount = InterlockedDecrement(&flowData->refCount);

	//if (0 != refCount)
	//{
	//	return;
	//}


	//卸载时未删除的在这里删除（不是TCP的）
	if (!flowData->deleting)
	{
		KLOCK_QUEUE_HANDLE lockHandle;

		sl_lock(&g_flowContextListLock, &lockHandle);

		if (flowData->listEntry.Flink && flowData->listEntry.Blink)
		{
			//KdPrint(("RemoveEntryList\n"));
			RemoveEntryList(&flowData->listEntry);
		}

		sl_unlock(&lockHandle);
	}


	//KdPrint(("free flowData:%p\n",flowData));
	if (flowData->processPath)
	{
		ExFreePoolWithTag(flowData->processPath, NF_TAG_NET);
		flowData->processPath = NULL;
	}
	if (flowData->processName)
	{
		ExFreePoolWithTag(flowData->processName, NF_TAG_NET);
		flowData->processName = NULL;
	}
	if (flowData->protocolName)
	{
		ExFreePoolWithTag(flowData->protocolName, NF_TAG_NET);
		flowData->protocolName = NULL;
	}

	ExFreePoolWithTag(flowData, NF_TAG_NET);
	flowData = NULL;
	
	return;
}

//删除上下文
VOID NTAPI WallFlowDeleteFn
(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
)
{
	FLOW_DATA** flowData;
	UINT64* flow;

	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);

	flow = &flowContext;
	flowData = ((FLOW_DATA**)flow);

	ReleaseFlowContext(*flowData);

	return;
}

//协议代码转为名称
VOID ProtocolIdToName(UINT16 id,LPWCH data)
{
	switch (id)
	{
	case 1:
		RtlCopyMemory(data,L"ICMP",sizeof(L"ICMP"));
		break;
	case 2:
		RtlCopyMemory(data, L"IGMP", sizeof(L"IGMP"));
		break;
	case 6:
		RtlCopyMemory(data, L"TCP", sizeof(L"TCP"));
		break;
	case 17:
		RtlCopyMemory(data, L"UDP", sizeof(L"UDP"));
		break;
	case 27:
		RtlCopyMemory(data, L"RDP", sizeof(L"RDP"));
		break;
	default:
		RtlCopyMemory(data, L"UNKNOWN", sizeof(L"UNKNOWN"));
		break;
	}
}

//获取目的ip
UINT32	NfGetRemoteIpV4(IN const UINT16	layerId, IN const FWPS_INCOMING_VALUES* inFixedValues)
{
	UINT32		RetValue = 0;

	switch (layerId)
	{
	case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;

	case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;

	case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;

	case FWPS_LAYER_STREAM_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;

	case FWPS_LAYER_DATAGRAM_DATA_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;

	case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;

	case FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
		break;
	}

	return RetValue;
}

//获取协议类型
USHORT	NfGetProtocolNumber(IN const UINT16		layerId, IN const FWPS_INCOMING_VALUES* inFixedValues)
{
	USHORT		RetValue = 0;

	switch (layerId)
	{
	case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16;
		break;

	case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint16;
		break;

	case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint16;
		break;

	case FWPS_LAYER_STREAM_V4:
		RetValue = IPPROTO_TCP;
		break;

	case FWPS_LAYER_DATAGRAM_DATA_V4:
		RetValue = IPPROTO_UDP;
		break;

	case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
	case FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint16;
		break;

	case FWPS_LAYER_INBOUND_TRANSPORT_V4:
	case FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint16;
		break;
	case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value.uint16;
		break;
	case FWPS_LAYER_ALE_BIND_REDIRECT_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_PROTOCOL].value.uint16;
		break;
	case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4:
		RetValue = inFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL].value.uint16;
		break;
	}

	return RetValue;
}


//创建上下文
UINT64 NfCoCreateFlowContext(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN const PMonitorMsg pNetWorkMsg)
{
	PFLOW_DATA	pFlowContext = NULL;
	BOOL isRet = FALSE;

	if(!pNetWorkMsg)
		goto FINAL;

	PNETWORKINFO pNetInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetInfo)
		goto FINAL;

	pFlowContext = ExAllocatePoolWithTag(NonPagedPool,sizeof(FLOW_DATA), NF_TAG_NET);
	if (!pFlowContext)
	{
		//KdPrint(("%s:%d(%s) [NetWork]ExAllocatePoolWithTag is err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlZeroMemory(pFlowContext, sizeof(FLOW_DATA));

	pFlowContext->flowHandle = inMetaValues->flowHandle;
	pFlowContext->deleting = FALSE;
	pFlowContext->localIp = pNetInfo->localIp;
	pFlowContext->remoteIP = pNetInfo->remoteIP;
	pFlowContext->ipType = pNetInfo->ipType;
	pFlowContext->localPort = pNetInfo->localPort;
	pFlowContext->remotePort = pNetInfo->remotePort;
	pFlowContext->pid = pNetWorkMsg->common.pid;
	pFlowContext->threadId = pNetInfo->threadId;
	pFlowContext->creatTime = pNetInfo->createTime;

	pFlowContext->ipProto = NfGetProtocolNumber(inFixedValues->layerId, inFixedValues);

	pFlowContext->processPath = (LPSTR)ExAllocatePoolWithTag(NonPagedPool, 512*sizeof(CHAR), NF_TAG_NET);
	if (!pFlowContext->processPath)
	{
		//KdPrint(("%s:%d(%s) [NetWork]ExAllocatePoolWithTag(pFlowContext->processPath) is err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pFlowContext->processPath, 512 * sizeof(CHAR));

	pFlowContext->processName = (LPSTR)ExAllocatePoolWithTag(NonPagedPool, 32 * sizeof(CHAR), NF_TAG_NET);
	if (!pFlowContext->processName)
	{
		//KdPrint(("%s:%d(%s) [NetWork]ExAllocatePoolWithTag(pFlowContext->processPath) is err\n", __FILE__, __LINE__, __FUNCTION__));

		goto FINAL;
	}
	RtlZeroMemory(pFlowContext->processName, 32 * sizeof(CHAR));
	
	pFlowContext->protocolName = (LPWCH)ExAllocatePoolWithTag(NonPagedPool, 12 * sizeof(WCHAR), NF_TAG_NET);
	if (!pFlowContext->protocolName)
	{
		//KdPrint(("%s:%d(%s) [NetWork]ExAllocatePoolWithTag(pFlowContext->processPath) is err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pFlowContext->protocolName, 12 * sizeof(WCHAR));

	if(((LPWCH)pNetWorkMsg->common.exe)[0] != L'\0')
		RtlCopyMemory(pFlowContext->processPath, pNetWorkMsg->common.exe, 512*sizeof(CHAR));

	if (pNetWorkMsg->common.comm[0] != '\0')
		RtlCopyMemory(pFlowContext->processName, pNetWorkMsg->common.comm, 32 * sizeof(CHAR));

	if (pNetInfo->protocolName[0] != L'\0')
		RtlCopyMemory(pFlowContext->protocolName, pNetInfo->protocolName, 12 * sizeof(WCHAR));

	//RtlStringCbCopyNW(pFlowContext->processPath, 260 * sizeof(WCHAR), pNetInfo->processPath, 260 * sizeof(WCHAR));
	//RtlStringCbCopyNW(pFlowContext->protocolName, 12 * sizeof(WCHAR), pNetInfo->protocolName, 12 * sizeof(WCHAR));


	KLOCK_QUEUE_HANDLE lockHandle;
	sl_lock(&g_flowContextListLock, &lockHandle);
	InsertTailList(&g_flowContextList, &pFlowContext->listEntry);
	sl_unlock(&lockHandle);

	isRet = TRUE;

FINAL:
	if (!isRet)
	{
		if (pFlowContext)
		{
			if (pFlowContext->processPath)
			{
				ExFreePoolWithTag(pFlowContext->processPath, NF_TAG_NET);
				pFlowContext->processPath = NULL;
			}

			if (pFlowContext->processName)
			{
				ExFreePoolWithTag(pFlowContext->processName, NF_TAG_NET);
				pFlowContext->processName = NULL;
			}
			ExFreePoolWithTag(pFlowContext, NF_TAG_NET);
			pFlowContext = NULL;
		}
		return (UINT64)NULL;
	}

	return (UINT64)pFlowContext;
}

//网络连接
void NTAPI WallALEConnectClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	classifyOut->actionType = FWP_ACTION_PERMIT;

	PMonitorMsg pNetWorkMsg = NULL;

	if (!GetTypeConfig(MT_SocketConnect) || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		goto FINAL;
	}
	
	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

	pNetWorkMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, NETWORK_ALLOCATESIZE, NF_TAG_NET);
	if (!pNetWorkMsg)
		goto FINAL;

	RtlZeroMemory(pNetWorkMsg, NETWORK_ALLOCATESIZE);

	PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetWorkInfo)
		goto FINAL;

	pNetWorkMsg->common.type = Monitor_Socket;
	pNetWorkInfo->threadId = (ULONG)PsGetCurrentThreadId();

	if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == FWPS_METADATA_FIELD_PROCESS_ID)
	{
		pNetWorkMsg->common.pid = (int)inMetaValues->processId;
	}
	else
	{
		pNetWorkMsg->common.pid = (int)PsGetCurrentProcessId();
	}
	
	GetCurrentTimeString(&pNetWorkMsg->common.time);

	//根据进程id获取进程名
	GetProcessNameByPID(pNetWorkMsg->common.pid, pNetWorkMsg->common.comm, sizeof(pNetWorkMsg->common.comm),&pNetWorkMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)pNetWorkMsg->common.pid, &pNetWorkInfo->createTime);

	pNetWorkInfo->type = MT_SocketConnect;
	pNetWorkInfo->ipType = IPV4;
	
	pNetWorkInfo->localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	pNetWorkInfo->remoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	pNetWorkInfo->localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
	pNetWorkInfo->remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
	ProtocolIdToName(NfGetProtocolNumber(inFixedValues->layerId, inFixedValues), pNetWorkInfo->protocolName);

	//if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH == FWPS_METADATA_FIELD_PROCESS_PATH)
	
	if (inMetaValues->processPath && inMetaValues->processPath->data && inMetaValues->processPath->size > 0)
	{
		if (inMetaValues->processPath->size < sizeof(pNetWorkMsg->common.exe))
		{
			RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, inMetaValues->processPath->size);
		}
		else
		{
			RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, 510);
		}

		if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else
	{
		if (pNetWorkMsg->common.pid > 0)
		{
			WCHARMAX processPath = { 0 };
			if (QueryProcessNamePath((DWORD)pNetWorkMsg->common.pid, processPath, sizeof(processPath)))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, processPath, sizeof(WCHARMAX));
				
				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
				{
					goto FINAL;
				}
			}
			else
			{
				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.comm, FALSE))
				{
					goto FINAL;
				}
			}
		}
		else
			goto FINAL;
	}

	SetNetWorkHeadList(pNetWorkMsg);

	//KdPrint(("%s:%d(%s) [连接网络]pid:%d,proname:%s,local:%u.%u.%u.%u:%d;remote=%u.%u.%u.%u:%d\n",
	//	__FILE__, __LINE__, __FUNCTION__, pNetWorkMsg->common.pid, pNetWorkMsg->common.exe,
	//	(pNetWorkInfo->localIp >> 24) & 0xFF, (pNetWorkInfo->localIp >> 16) & 0xFF, (pNetWorkInfo->localIp >> 8) & 0xFF, pNetWorkInfo->localIp & 0xFF,
	//	pNetWorkInfo->localPort,
	//	(pNetWorkInfo->remoteIP >> 24) & 0xFF, (pNetWorkInfo->remoteIP >> 16) & 0xFF, (pNetWorkInfo->remoteIP >> 8) & 0xFF, pNetWorkInfo->remoteIP & 0xFF,
	//	pNetWorkInfo->remotePort));

	//KdPrint(("%s:%d(%s)[连接网络]\n",__FILE__,__LINE__,__FUNCTION__));

	if (0 != flowContext || 0 == inMetaValues->flowHandle)
	{
		//KdPrint(("%s:%d(%s) [NetWork]flowContext is not 0\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	//创建上下文
	flowContext = NfCoCreateFlowContext(inFixedValues, inMetaValues, pNetWorkMsg);
	if (0 == flowContext)
	{
		//KdPrint(("%s:%d(%s) [NetWork]flowContext is not 0\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	PFLOW_DATA pFlowContext = (PFLOW_DATA)flowContext;

	//TCP
	if (IPPROTO_TCP == pFlowContext->ipProto && gAleTransCalloutId)
	{
		NTSTATUS status = FwpsFlowAssociateContext(pFlowContext->flowHandle,
			FWPS_LAYER_STREAM_V4,
			gAleTransCalloutId,
			flowContext);

		if (NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_EXISTS)
		{
			//InterlockedIncrement(&pFlowContext->refCount);
			pFlowContext->ContextFlag |= NF_CONTEXTFLAG_STREAM_ASSOCIATED;
		}
		else
		{
			KdPrint(("%s:%d(%s) [NetWork]FwpsFlowAssociateContext(IPPROTO_TCP) err:%p\n",
				__FILE__, __LINE__, __FUNCTION__, status));
		}	
	}

	if(IPPROTO_UDP == pFlowContext->ipProto && gAleDataCalloutId)
	{
		NTSTATUS status = FwpsFlowAssociateContext(pFlowContext->flowHandle,
			FWPS_LAYER_DATAGRAM_DATA_V4,
			gAleDataCalloutId,
			flowContext);
		if (NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_EXISTS)
		{
			//InterlockedIncrement(&pFlowContext->refCount);
			pFlowContext->ContextFlag |= NF_CONTEXTFLAG_DATAGRAM_ASSOCIATED;
		}
		else
		{
			KdPrint(("%s:%d(%s) [NetWork]FwpsFlowAssociateContext(IPPROTO_UDP) err\n", __FILE__, __LINE__, __FUNCTION__));
		}
	}
	
	//会崩溃
	//if (gAleCloseCalloutId)
	//{
	//	NTSTATUS status = FwpsFlowAssociateContext(pFlowContext->flowHandle,
	//		FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4,
	//		gAleCloseCalloutId,
	//		flowContext);
	//	if (NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_EXISTS)
	//	{
	//		pFlowContext->ContextFlag |= NF_CONTEXTFLAG_CLOSUSER_ASSOCIATED;
	//	}
	//	else
	//	{
	//		KdPrint(("%s:%d(%s) [NetWork]FwpsFlowAssociateContext(STATUS_OBJECT_NAME_EXISTS) err\n", __FILE__, __LINE__, __FUNCTION__));
	//	}
	//}


	//禁止联网（设置“行动类型”为FWP_ACTION_BLOCK）
	//if(wcsstr((PWCHAR)inMetaValues->processPath->data,L"chrome.exe"))
	//{
	// classifyOut->actionType = FWP_ACTION_BLOCK;
	// classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	// classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	//}

FINAL:
	if (pNetWorkMsg)
	{
		ExFreePoolWithTag(pNetWorkMsg, NF_TAG_NET);
		pNetWorkMsg = NULL;
	}
	return;
}

//获取网络数据
PX_BUFFER	GetPacketData(FWPS_STREAM_DATA* streamData, FLOW_DATA* pFlowData)
{
	ULONG			bytesCopied = 0;
	CHAR*			pBuffer = NULL;
	POOL_TYPE		PoolType = NonPagedPool;
	PX_BUFFER		pNetBuffer = NULL;

	if (KeGetCurrentIrql() < DISPATCH_LEVEL)
	{
		PoolType = PagedPool;
	}

	if (streamData->dataLength == 0)
	{
		goto FINAL;
	}

	pNetBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(X_BUFFER) + streamData->dataLength + 1, NF_TAG_NET);
	if (NULL == pNetBuffer)
	{
		goto FINAL;
	}
	RtlZeroMemory(pNetBuffer, sizeof(X_BUFFER) + streamData->dataLength + 1);

	pBuffer = pNetBuffer->Data;

	FwpsCopyStreamDataToBuffer(
		streamData,
		pBuffer,
		streamData->dataLength + 1,
		(SIZE_T*)&bytesCopied);
	if (bytesCopied == 0)
	{
		//KdPrint(("[ERROR] FwpsCopyStreamDataToBuffer\n"));
		goto FINAL;
	}

	pBuffer[bytesCopied] = '\0';

	pNetBuffer->pBuffer = pNetBuffer->Data;
	pNetBuffer->cbBuffer = bytesCopied;

FINAL:
	if (0 == bytesCopied)
	{
		if (pNetBuffer)
		{
			ExFreePoolWithTag(pNetBuffer, NF_TAG_NET);
			pNetBuffer = NULL;
		}
	}

	return pNetBuffer;
}

VOID GetConTextData(PMonitorMsg pNetWorkMsg, PFLOW_DATA pFlowData)
{
	if (!pNetWorkMsg)
		return;
	PNETWORKINFO pNetInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetInfo)
		return;

	pNetInfo->localIp = pFlowData->localIp;
	pNetInfo->localPort = pFlowData->localPort;
	pNetWorkMsg->common.pid = pFlowData->pid;
	pNetInfo->remoteIP = pFlowData->remoteIP;
	pNetInfo->remotePort = pFlowData->remotePort;
	pNetInfo->threadId = pFlowData->threadId;
	pNetInfo->createTime = pFlowData->creatTime;

	RtlCopyMemory(pNetWorkMsg->common.exe, pFlowData->processPath, 512*sizeof(CHAR));
	RtlCopyMemory(pNetWorkMsg->common.comm, pFlowData->processName, 32 * sizeof(CHAR));
	RtlCopyMemory(pNetInfo->protocolName, pFlowData->protocolName, 12 * sizeof(WCHAR));

	//RtlStringCbCopyNW(pNetInfo->processPath, 260 * sizeof(WCHAR), pFlowData->processPath, 260 * sizeof(WCHAR));
	//RtlStringCbCopyNW(pNetInfo->protocolName, 12 * sizeof(WCHAR), pFlowData->protocolName, 12 * sizeof(WCHAR));
}

//监测网络数据传输
void NTAPI WallALELayerStreamClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	classifyOut->actionType = FWP_ACTION_PERMIT;

	PMonitorMsg pNetWorkMsg = NULL;

	if (!GetTypeConfig(Monitor_Socket) || 0 == flowContext || layerData == NULL || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		goto FINAL;
	}

	FWPS_STREAM_CALLOUT_IO_PACKET* streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
	if (!streamPacket || !streamPacket->streamData)
		goto FINAL;

	PFLOW_DATA pFlowData = (PFLOW_DATA)flowContext;
	if (NULL == pFlowData || pFlowData->ipProto != IPPROTO_TCP)
		goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

	pNetWorkMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, NETWORK_ALLOCATESIZE, NF_TAG_NET);
	if (NULL == pNetWorkMsg)
		goto FINAL;

	RtlZeroMemory(pNetWorkMsg, NETWORK_ALLOCATESIZE);

	PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetWorkInfo)
		goto FINAL;
	
	pNetWorkMsg->common.type = Monitor_Socket;
	GetConTextData(pNetWorkMsg, pFlowData);

	//根据进程id获取进程创建时间
	//GetProcessCreateTimeByPID((DWORD)pNetWorkMsg->common.pid, &pNetWorkInfo->createTime);

	if (((LPWCH)pNetWorkMsg->common.exe)[0] != L'\0')
	{
		if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	GetCurrentTimeString(&pNetWorkMsg->common.time);

	if (IPPROTO_TCP == pFlowData->ipProto)
	{
		//接收数据包
		if ((streamPacket->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) == FWPS_STREAM_FLAG_RECEIVE)
		{
			if (!GetTypeConfig(MT_SocketRecv))
				goto FINAL;

			pNetWorkInfo->type = MT_SocketRecv;

			KdPrint(("%s:%d(%s)[接收数据包]\n", __FILE__, __LINE__, __FUNCTION__));
			//KdPrint(("%s:%d(%s) [接收数据包]pid:%d,processParh:%S,local:%u.%u.%u.%u:%d;remote=%u.%u.%u.%u:%d\n", 
			//	__FILE__, __LINE__, __FUNCTION__, pNetWorkMsg->common.pid, pNetWorkMsg->common.exe,
			//	(pNetWorkInfo->localIp >> 24) & 0xFF, (pNetWorkInfo->localIp >> 16) & 0xFF, (pNetWorkInfo->localIp >> 8) & 0xFF, pNetWorkInfo->localIp & 0xFF,
			//	pNetWorkInfo->localPort,
			//	(pNetWorkInfo->remoteIP >> 24) & 0xFF, (pNetWorkInfo->remoteIP >> 16) & 0xFF, (pNetWorkInfo->remoteIP >> 8) & 0xFF, pNetWorkInfo->remoteIP & 0xFF,
			//	pNetWorkInfo->remotePort));

			SetNetWorkHeadList(pNetWorkMsg);
		}
		//发送数据包
		else if ((streamPacket->streamData->flags & FWPS_STREAM_FLAG_SEND) == FWPS_STREAM_FLAG_SEND)
		{
			if (!GetTypeConfig(MT_SocketSend))
				goto FINAL;
			pNetWorkInfo->type = MT_SocketSend;
			KdPrint(("%s:%d(%s)[发送数据包]\n", __FILE__, __LINE__, __FUNCTION__));

			//KdPrint(("%s:%d(%s) [发送数据包]pid:%d,processParh:%S,local:%u.%u.%u.%u:%d;remote=%u.%u.%u.%u:%d\n", 
			//	__FILE__, __LINE__, __FUNCTION__, pNetWorkMsg->common.pid, pNetWorkMsg->common.exe,
			//	(pNetWorkInfo->localIp >> 24) & 0xFF, (pNetWorkInfo->localIp >> 16) & 0xFF, (pNetWorkInfo->localIp >> 8) & 0xFF, pNetWorkInfo->localIp & 0xFF,
			//	pNetWorkInfo->localPort,
			//	(pNetWorkInfo->remoteIP >> 24) & 0xFF, (pNetWorkInfo->remoteIP >> 16) & 0xFF, (pNetWorkInfo->remoteIP >> 8) & 0xFF, pNetWorkInfo->remoteIP & 0xFF,
			//	pNetWorkInfo->remotePort));

			if (streamPacket->streamData->dataLength)
			{
				//KdPrint(("%s:%d [send]pid:%d,proname:%S\n", __FILE__, __LINE__, pNetWorkInfo->pid, pNetWorkInfo->processPath));

				//PX_BUFFER	pXBuffer = NULL;
				//pXBuffer = GetPacketData(streamPacket->streamData, pFlowData);

				//KdPrint(("===data:%s\n", pXBuffer->pBuffer[0]));
			}

			SetNetWorkHeadList(pNetWorkMsg);

			//禁止发送
			//classifyOut->actionType = FWP_ACTION_NONE_NO_MATCH;
		}
	}

	//禁止发送
	//classifyOut->actionType = FWP_ACTION_NONE_NO_MATCH;

FINAL:
	if (pNetWorkMsg)
	{
		ExFreePoolWithTag(pNetWorkMsg, NF_TAG_NET);
		pNetWorkMsg = NULL;
	}

	return;
}

//DNS解析 FWPM_LAYER_DATAGRAM_DATA_V4 
void NTAPI WallALEDnsClassify(
	IN  const FWPS_INCOMING_VALUES* inFixedValues,
	IN  const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN  VOID*                       packet,
	IN  const void*                 classifyContext,
	IN  const FWPS_FILTER*          filter,
	IN  UINT64                      flowContext,
	OUT FWPS_CLASSIFY_OUT*          classifyOut
) {
	classifyOut->actionType = FWP_ACTION_PERMIT;

	PMonitorMsg pNetWorkMsg = NULL;
	PVOID pDataBuffer = NULL;

	//KdPrint(("========DNS start===%d,%d,%d,%d,%d\n", KeGetCurrentIrql(), flowContext, 
		//inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8,
		//inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16,
		//inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32));

	if (/*!GetWorkStatus() ||*/ KeGetCurrentIrql() > DISPATCH_LEVEL || 
		0 == flowContext ||inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8 != IPPROTO_UDP ||
		inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16 != 53 ||
		inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32 != FWP_DIRECTION_INBOUND)
	{
		goto FINAL;
	}

	PNET_BUFFER pNetBuffer = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)packet);
	if (pNetBuffer != NULL)
	{
		ULONG nDataLength = NET_BUFFER_DATA_LENGTH(pNetBuffer);
		if (nDataLength < 13)
		{
			KdPrint(("%s:%d(%s)[解析DNS error]%d\n", __FILE__, __LINE__, __FUNCTION__, nDataLength));
			goto FINAL;
		}

		pDataBuffer = ExAllocatePoolWithTag(NonPagedPool, nDataLength, NF_TAG_NET);
		if (!pDataBuffer)
			goto FINAL;
		RtlZeroMemory(pDataBuffer, nDataLength);
		
		//<= DISPATCH_LEVEL
		PVOID pDataBuffer0 = NdisGetDataBuffer(pNetBuffer, nDataLength, pDataBuffer, 1, 0);
		if (pDataBuffer0)
		{
			PCHAR  pszQuery = (PCHAR)pDataBuffer0 + 12/*sizeof DNS header*/;
			if (NULL == pszQuery)
			{
				goto FINAL;
			}

			CHAR   szQueryName[MAX_PATH] = { 0 };
			CHAR   cbLabel = pszQuery[0];
			UINT32 nLen = 1;
			while (cbLabel != 0)
			{
				if (nLen >= 250)
					break;
				for (CHAR i = 0; i < cbLabel; i++)
				{
					if (nLen >= 250 || nDataLength < nLen+13)
						break;
					szQueryName[nLen - 1] = pszQuery[nLen];
					nLen++;
				}

				if (nLen >= 250 || nDataLength < nLen + 13)
					break;

				cbLabel = pszQuery[nLen];
				szQueryName[nLen - 1] = cbLabel != 0 ? '.' : 0;
				nLen++;
			}

			if (szQueryName[0] == '\0')
				goto FINAL;

			//KIRQL oldIrql;
			//KeRaiseIrql(PASSIVE_LEVEL, &oldIrql);

			//ANSI_STRING ansiDnsName = { 0 };
			//RtlInitAnsiString(&ansiDnsName, szQueryName);

			//UNICODE_STRING unicodeDnsName = { 0 };
			//NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodeDnsName, &ansiDnsName, TRUE);
			//if (!NT_SUCCESS(status))
			//{
			//	ExFreePoolWithTag(pDataBuffer, 'Tsnd');
			//	return;
			//}
			
			//status = RtlStringCbCopyNW(pNetWorkInfo->dnsName, 255 * sizeof(WCHAR), unicodeDnsName.Buffer, unicodeDnsName.Length);
			//if (!NT_SUCCESS(status))
			//{
			//	ExFreePoolWithTag(pDataBuffer, 'Tsnd');
			//	RtlFreeUnicodeString(&unicodeDnsName);
			//	return;
			//}

			//RtlFreeUnicodeString(&unicodeDnsName);

			//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

			pNetWorkMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, NETWORK_ALLOCATESIZE, NF_TAG_NET);
			if (!pNetWorkMsg)
				goto FINAL;
			RtlZeroMemory(pNetWorkMsg, NETWORK_ALLOCATESIZE);

			PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)pNetWorkMsg->data;
			if (!pNetWorkInfo)
				goto FINAL;

			PFLOW_DATA pFlowData = (PFLOW_DATA)flowContext;
			GetConTextData(pNetWorkMsg, pFlowData);

			//if (!IsAllowProcess(pNetWorkInfo->processPath))
			//	goto FINAL;

			GetCurrentTimeString(&pNetWorkMsg->common.time);

			//根据进程id获取进程名
			GetProcessNameByPID(pNetWorkMsg->common.pid, pNetWorkMsg->common.comm, sizeof(pNetWorkMsg->common.comm), &pNetWorkMsg->common.ppid);
			//根据进程id获取进程创建时间
			GetProcessCreateTimeByPID((DWORD)pNetWorkMsg->common.pid, &pNetWorkInfo->createTime);

			//pNetWorkInfo->type = NET_DNS;

			//RtlCopyMemory(pNetWorkInfo->dnsName, szQueryName, strlen(szQueryName));

			SetNetWorkHeadList(pNetWorkMsg);

			//KdPrint(("%S %s:%d(%s)[解析DNS]%s\n",pNetWorkInfo->time,__FILE__,__LINE__,__FUNCTION__,pNetWorkInfo->dnsName));

			//KdPrint(("%S %s:%d(%s) [解析DNS]pid:%d,processParh:%S,DNS:%S\n",
			//	pNetWorkInfo->time, __FILE__, __LINE__, __FUNCTION__, pNetWorkInfo->pid, pNetWorkInfo->processPath, 
			//	pNetWorkInfo->dnsName));

			//不解析DNS
			//if (strcmp(szQueryName,"www.baidu.com") == 0)
			//{
			//	 classifyOut->actionType = FWP_ACTION_BLOCK;
			//	 classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
			//	 classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
			//}
			
		}		
	}

FINAL:
	if (pDataBuffer)
	{
		ExFreePoolWithTag(pDataBuffer, NF_TAG_NET);
		pDataBuffer = NULL;
	}

	if (pNetWorkMsg)
	{
		ExFreePoolWithTag(pNetWorkMsg, NF_TAG_NET);
		pNetWorkMsg = NULL;
	}
	return;
}

//创建端口
void NTAPI WallALECreatePortClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	classifyOut->actionType = FWP_ACTION_PERMIT;

	PMonitorMsg pNetWorkMsg = NULL;

	if (!GetTypeConfig(MT_SocketCreate) || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		goto FINAL;
	}

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

	pNetWorkMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, NETWORK_ALLOCATESIZE, NF_TAG_NET);
	if (!pNetWorkMsg)
		goto FINAL;

	RtlZeroMemory(pNetWorkMsg, NETWORK_ALLOCATESIZE);

	PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetWorkInfo)
		goto FINAL;

	pNetWorkMsg->common.type = Monitor_Socket;
	if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == FWPS_METADATA_FIELD_PROCESS_ID)
	{
		pNetWorkMsg->common.pid = (int)inMetaValues->processId;
	}
	else
	{
		pNetWorkMsg->common.pid = (int)PsGetCurrentProcessId();
	}

	pNetWorkInfo->threadId = (ULONG)PsGetCurrentThreadId();
	GetCurrentTimeString(&pNetWorkMsg->common.time);

	//根据进程id获取进程名
	GetProcessNameByPID(pNetWorkMsg->common.pid, pNetWorkMsg->common.comm, sizeof(pNetWorkMsg->common.comm), &pNetWorkMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)pNetWorkMsg->common.pid, &pNetWorkInfo->createTime);

	pNetWorkInfo->type = MT_SocketCreate;
	pNetWorkInfo->ipType = IPV4;
	pNetWorkInfo->localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	pNetWorkInfo->localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_PORT].value.uint16;

	ProtocolIdToName(NfGetProtocolNumber(inFixedValues->layerId, inFixedValues), pNetWorkInfo->protocolName);

	//if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH == FWPS_METADATA_FIELD_PROCESS_PATH)
	//{
		if (inMetaValues->processPath && inMetaValues->processPath->data && inMetaValues->processPath->size > 0)
		{
			if (inMetaValues->processPath->size < sizeof(pNetWorkMsg->common.exe))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, inMetaValues->processPath->size);
			}
			else
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, 510);
			}

			if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
			{
				goto FINAL;
			}
		}
	//}
	else
	{
		if (pNetWorkMsg->common.pid > 0)
		{
			WCHARMAX processPath = { 0 };
			if (QueryProcessNamePath((DWORD)pNetWorkMsg->common.pid, processPath, sizeof(processPath)))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, processPath, sizeof(WCHARMAX));

				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
				{
					goto FINAL;
				}
			}
			else
			{
				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.comm, FALSE))
				{
					goto FINAL;
				}
			}
		}
		else
			goto FINAL;
	}


	KdPrint(("%s:%d(%s) [创建端口]pid:%d,proname:%s,local:%u.%u.%u.%u:%d;remote=%u.%u.%u.%u:%d\n",
		__FILE__, __LINE__, __FUNCTION__, pNetWorkMsg->common.pid, pNetWorkMsg->common.comm,
		(pNetWorkInfo->localIp >> 24) & 0xFF, (pNetWorkInfo->localIp >> 16) & 0xFF, (pNetWorkInfo->localIp >> 8) & 0xFF, pNetWorkInfo->localIp & 0xFF,
		pNetWorkInfo->localPort,
		(pNetWorkInfo->remoteIP >> 24) & 0xFF, (pNetWorkInfo->remoteIP >> 16) & 0xFF, (pNetWorkInfo->remoteIP >> 8) & 0xFF, pNetWorkInfo->remoteIP & 0xFF,
		pNetWorkInfo->remotePort));

	SetNetWorkHeadList(pNetWorkMsg);


	//禁止联网（设置“行动类型”为FWP_ACTION_BLOCK）
	//if(wcsstr((PWCHAR)inMetaValues->processPath->data,L"chrome.exe"))
	//{
	// classifyOut->actionType = FWP_ACTION_BLOCK;
	// classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	// classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	//}

FINAL:
	if (pNetWorkMsg)
	{
		ExFreePoolWithTag(pNetWorkMsg, NF_TAG_NET);
		pNetWorkMsg = NULL;
	}
	return;
}

//绑定端口
void NTAPI WallALEBindPortClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	classifyOut->actionType = FWP_ACTION_PERMIT;

	PMonitorMsg pNetWorkMsg = NULL;

	if (!GetTypeConfig(MT_SocketBind) || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		goto FINAL;
	}

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

	pNetWorkMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, NETWORK_ALLOCATESIZE, NF_TAG_NET);
	if (!pNetWorkMsg)
		goto FINAL;

	RtlZeroMemory(pNetWorkMsg, NETWORK_ALLOCATESIZE);

	PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetWorkInfo)
		goto FINAL;

	pNetWorkMsg->common.type = Monitor_Socket;
	if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == FWPS_METADATA_FIELD_PROCESS_ID)
	{
		pNetWorkMsg->common.pid = (int)inMetaValues->processId;
	}
	else
	{
		pNetWorkMsg->common.pid = (int)PsGetCurrentProcessId();
	}
	pNetWorkInfo->threadId = (ULONG)PsGetCurrentThreadId();

	GetCurrentTimeString(&pNetWorkMsg->common.time);

	pNetWorkInfo->type = MT_SocketBind;
	pNetWorkInfo->ipType = IPV4;
	pNetWorkInfo->localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS].value.uint32;
	pNetWorkInfo->localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16;

	ProtocolIdToName(NfGetProtocolNumber(inFixedValues->layerId, inFixedValues), pNetWorkInfo->protocolName);

	//根据进程id获取进程名
	GetProcessNameByPID(pNetWorkMsg->common.pid, pNetWorkMsg->common.comm, sizeof(pNetWorkMsg->common.comm), &pNetWorkMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)pNetWorkMsg->common.pid, &pNetWorkInfo->createTime);


	//if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH == FWPS_METADATA_FIELD_PROCESS_PATH)
	//{
		if (inMetaValues->processPath && inMetaValues->processPath->data && inMetaValues->processPath->size > 0)
		{
			if (inMetaValues->processPath->size < sizeof(pNetWorkMsg->common.exe))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, inMetaValues->processPath->size);
			}
			else
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, 510);
			}

			//if (inMetaValues->processPath->size < sizeof(WCHARMAX))
			//	RtlCopyMemory(pNetWorkInfo->processPath, inMetaValues->processPath->data, inMetaValues->processPath->size);
			if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
			{
				goto FINAL;
			}
		}
	//}
	else
	{
		if (pNetWorkMsg->common.pid > 0)
		{
			WCHARMAX processPath = { 0 };
			if (QueryProcessNamePath((DWORD)pNetWorkMsg->common.pid, processPath, sizeof(processPath)))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, processPath, sizeof(WCHARMAX));

				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
				{
					goto FINAL;
				}
			}
			else
			{
				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.comm, FALSE))
				{
					goto FINAL;
				}
			}
		}
		else
			goto FINAL;
	}

	SetNetWorkHeadList(pNetWorkMsg);

	KdPrint(("%s:%d(%s) [绑定端口]pid:%d,proname:%S,protocolName:%S,local:%u.%u.%u.%u:%d\n",
		__FILE__, __LINE__, __FUNCTION__, pNetWorkMsg->common.pid, pNetWorkMsg->common.exe, pNetWorkInfo->protocolName,
		(pNetWorkInfo->localIp >> 24) & 0xFF, (pNetWorkInfo->localIp >> 16) & 0xFF, (pNetWorkInfo->localIp >> 8) & 0xFF, pNetWorkInfo->localIp & 0xFF,
		pNetWorkInfo->localPort));

FINAL:
	if (pNetWorkMsg)
	{
		ExFreePoolWithTag(pNetWorkMsg, NF_TAG_NET);
		pNetWorkMsg = NULL;
	}
	return;
}

//关闭连接
void NTAPI WallALECloseClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	classifyOut->actionType = FWP_ACTION_PERMIT;

	PMonitorMsg pNetWorkMsg = NULL;

	if (!GetTypeConfig(MT_SocketClose) || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		goto FINAL;
	}	

	//PFLOW_DATA pFlowData = (PFLOW_DATA)flowContext;
	//if (NULL == pFlowData)
	//	goto FINAL;

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

	pNetWorkMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, NETWORK_ALLOCATESIZE, NF_TAG_NET);
	if (NULL == pNetWorkMsg)
		goto FINAL;

	RtlZeroMemory(pNetWorkMsg, NETWORK_ALLOCATESIZE);

	PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)pNetWorkMsg->data;
	if (!pNetWorkInfo)
		goto FINAL;

	pNetWorkMsg->common.type = Monitor_Socket;
	if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == FWPS_METADATA_FIELD_PROCESS_ID)
	{
		pNetWorkMsg->common.pid = (int)inMetaValues->processId;
	}
	else
	{
		pNetWorkMsg->common.pid = (int)PsGetCurrentProcessId();
	}

	pNetWorkInfo->type = MT_SocketClose;
	GetCurrentTimeString(&pNetWorkMsg->common.time);

	//GetConTextData(pNetWorkInfo, pFlowData);

	pNetWorkInfo->type = MT_SocketClose;
	pNetWorkInfo->ipType = IPV4;

	pNetWorkInfo->localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS].value.uint32;
	pNetWorkInfo->localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT].value.uint16;
	pNetWorkInfo->remoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_ADDRESS].value.uint32;
	pNetWorkInfo->remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_PORT].value.uint16;

	ProtocolIdToName(NfGetProtocolNumber(inFixedValues->layerId, inFixedValues), pNetWorkInfo->protocolName);

	//根据进程id获取进程名
	GetProcessNameByPID(pNetWorkMsg->common.pid, pNetWorkMsg->common.comm, sizeof(pNetWorkMsg->common.comm), &pNetWorkMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)pNetWorkMsg->common.pid, &pNetWorkInfo->createTime);

	//if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH == FWPS_METADATA_FIELD_PROCESS_PATH)
	//{
		if (inMetaValues->processPath && inMetaValues->processPath->data && inMetaValues->processPath->size > 0)
		{
			if (inMetaValues->processPath->size < sizeof(pNetWorkMsg->common.exe))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, inMetaValues->processPath->size);
			}
			else
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, inMetaValues->processPath->data, 510);
			}

			//if (inMetaValues->processPath->size < sizeof(WCHARMAX))
			//	RtlCopyMemory(pNetWorkInfo->processPath, inMetaValues->processPath->data, inMetaValues->processPath->size);
			if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
			{
				goto FINAL;
			}
		}
	//}
	else
	{	
		if (pNetWorkMsg->common.pid > 0)
		{	
			WCHARMAX processPath = { 0 };
			if (QueryProcessNamePath((DWORD)pNetWorkMsg->common.pid, processPath, sizeof(processPath)))
			{
				RtlCopyMemory(pNetWorkMsg->common.exe, processPath, sizeof(WCHARMAX));
				
				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.exe, TRUE))
				{
					goto FINAL;
				}
			}
			else
			{
				if (!IsAllowData(POLICY_EXE_LIST, pNetWorkMsg->common.comm, FALSE))
				{
					goto FINAL;
				}
			}
		}
		else
			goto FINAL;

	}

	KdPrint(("%s:%d(%s) [关闭连接]\n", __FILE__, __LINE__, __FUNCTION__));
	//KdPrint(("%s:%d(%s) [关闭连接]pid:%d,processName:%s,protocolName:%S,local:%u.%u.%u.%u:%d\n",
	//	__FILE__, __LINE__, __FUNCTION__, pNetWorkMsg->common.pid, pNetWorkMsg->common.comm, pNetWorkInfo->protocolName,
	//	(pNetWorkInfo->localIp >> 24) & 0xFF, (pNetWorkInfo->localIp >> 16) & 0xFF, (pNetWorkInfo->localIp >> 8) & 0xFF, pNetWorkInfo->localIp & 0xFF,
	//	pNetWorkInfo->localPort));


	SetNetWorkHeadList(pNetWorkMsg);

	//禁止发送
	//classifyOut->actionType = FWP_ACTION_NONE_NO_MATCH;

FINAL:
	if (pNetWorkMsg)
	{
		ExFreePoolWithTag(pNetWorkMsg, NF_TAG_NET);
		pNetWorkMsg = NULL;
	}
}

//设置数据List
BOOL SetNetWorkHeadList(PMonitorMsg pNetWorkMsg)
{
	if (!pNetWorkMsg)
		return FALSE;
	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(NETWORKINFO);

	PDEVBUFFER pInfo = (PDEVBUFFER)NetWorkPacketAllocate(NETWORK_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [NetWork]NetWorkPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		return FALSE;
	}

	RtlCopyMemory(pInfo->dataBuffer, pNetWorkMsg, NETWORK_ALLOCATESIZE);

	//获取数据量
	CheckNetWorkDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_netWorkData.lock, &lh);
	InsertHeadList(&g_netWorkData.pending, &pInfo->pEntry);

	g_netWorkData.dataSize++;
	sl_unlock(&lh);

	PushInfo(Monitor_Socket);
	return TRUE;
}

//从List中申请内存
PDEVBUFFER NetWorkPacketAllocate(int lens)
{
	PDEVBUFFER pNetWorkbuf = NULL;
	if (lens <= 0)
		return pNetWorkbuf;

	pNetWorkbuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_netWorkList);
	if (!pNetWorkbuf)
		return pNetWorkbuf;

	RtlZeroMemory(pNetWorkbuf, sizeof(DEVBUFFER));

	pNetWorkbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_NET_BUF);
	if (!pNetWorkbuf->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_netWorkList, pNetWorkbuf);
		pNetWorkbuf = NULL;
		return pNetWorkbuf;
	}
	pNetWorkbuf->dataLength = lens;
	RtlZeroMemory(pNetWorkbuf->dataBuffer, lens);
	
	return pNetWorkbuf;
}

//释放内存
void NetWorkPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;
	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_NET_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_netWorkList, packet);
}

//获取存储数据信息
PDEVDATA GetNetWorkCtx()
{
	return &g_netWorkData;
}

//获取数据量
VOID CheckNetWorkDataNum()
{
	if (g_netWorkData.dataSize > NETWORK_DATAMAXNUM)
	{
		CleanNetWork();

		//KLOCK_QUEUE_HANDLE lh;
		//sl_lock(&g_netWorkData.lock, &lh);
		//g_netWorkData.dataSize = 0;
		//sl_unlock(&lh);
	}
}