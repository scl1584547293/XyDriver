#pragma once
#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "public.h"
#include "config.h"
#include "devctrl.h"

#define INITGUID
#include <guiddef.h>

#define			NF_CONTEXTFLAG_CLOSUSER_ASSOCIATED						0x1
#define			NF_CONTEXTFLAG_STREAM_ASSOCIATED						0x2
#define			NF_CONTEXTFLAG_DATAGRAM_ASSOCIATED						0x4

typedef struct _FLOW_DATA
{
	LIST_ENTRY				listEntry;
	UINT64					flowHandle;
	BOOL					deleting;
	USHORT					ipProto;
	//ULONG			refCount;
	ULONG ContextFlag;


	//进程id
	ULONG pid;
	//线程id
	ULONG threadId;
	//进程路径
	LPSTR processPath;
	//进程名
	LPSTR processName;
	//ip类型
	ULONG ipType;
	//源ip
	DWORD localIp;
	//源端口
	DWORD localPort;
	//目的ip
	DWORD remoteIP;
	//目的端口
	DWORD remotePort;
	//协议名
	LPWCH protocolName;
	//进程创建时间
	LONGLONG creatTime;

} FLOW_DATA, *PFLOW_DATA;

typedef struct _X_BUFFER
{
	UCHAR*		pBuffer;
	ULONG		cbBuffer;
	UCHAR		Data[1];
} X_BUFFER, *PX_BUFFER;

enum IP_TYPE {
	IPV4 = 0,
	IPV6,
};

//enum NETWORK_TYPE {
//	//连接网络
//	NET_CONNECT = 0,
//	//接收数据
//	NET_GETDATA,
//	//发送数据
//	NET_SENDDATA,
//	//解析DNS
//	NET_DNS,
//	//创建端口
//	NET_CREATEPORT,
//	//绑定端口
//	NET_BINDPORT,
//	//关闭连接
//	NET_CLOSENET
//};

typedef struct _NETWORKINFO
{
	//网络操作类型
	MonitorTypeSocket_EM type;
	//线程id
	ULONG threadId;
	//ip类型
	ULONG ipType;

	//源ip
	DWORD localIp;
	//源端口
	DWORD localPort;
	//目的ip
	DWORD remoteIP;
	//目的端口
	DWORD remotePort;
	//协议名
	WCHAR protocolName[12];
	//DNS名字
	//CHAR dnsName[MAX_PATH];
	//进程创建时间
	LONGLONG createTime;
}NETWORKINFO, *PNETWORKINFO;

//注册WFP
NTSTATUS RegisterCalloutForLayer
(
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT UINT32* calloutId,
	OUT UINT64* filterId
);

//初始化网络模块
NTSTATUS WallRegisterCallouts(PDRIVER_OBJECT  DevObj);
//卸载网络
NTSTATUS WallUnRegisterCallouts();
NTSTATUS NTAPI WallNotifyFn
(
	IN FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
	IN const GUID  *filterKey,
	IN FWPS_FILTER  *filter
);
VOID NTAPI ReleaseFlowContext(PFLOW_DATA flowData);
VOID NTAPI WallFlowDeleteFn
(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
);

//获取TCP协议名
VOID ProtocolIdToName(UINT16 id, LPWCH data);
UINT32	NfGetRemoteIpV4(IN const UINT16		layerId, IN const FWPS_INCOMING_VALUES* inFixedValues);
USHORT	NfGetProtocolNumber(IN const UINT16		layerId, IN const FWPS_INCOMING_VALUES* inFixedValues);
//创建上下文
UINT64 NfCoCreateFlowContext(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN const PMonitorMsg pNetWorkMsg);

//监测网络连接
void NTAPI WallALEConnectClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
);

//监测DNS解析
void NTAPI WallALEDnsClassify(
	IN  const FWPS_INCOMING_VALUES* inFixedValues,
	IN  const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN  VOID*                       packet,
	IN  const void*                 classifyContext,
	IN  const FWPS_FILTER*          filter,
	IN  UINT64                      flowContext,
	OUT FWPS_CLASSIFY_OUT*          classifyOut
);

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
);

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
);

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
);

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
);


BOOL SetNetWorkHeadList(PMonitorMsg pNetWorkMsg);

VOID CleanNetWork();
//从List中申请内存
PDEVBUFFER NetWorkPacketAllocate(int lens);
//释放内存
void NetWorkPacketFree(PDEVBUFFER packet);
//获取网络数据
PDEVDATA GetNetWorkCtx();

VOID GetConTextData(PMonitorMsg pNetWorkMsg, PFLOW_DATA pFlowData);

//获取数据量
VOID CheckNetWorkDataNum();
