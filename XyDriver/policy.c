#include "policy.h"
#include "public.h"
#include "config.h"

#define POLICYNUM POLICY_FILE_LIST+1
//保存配置的链表
static LIST_ENTRY g_policyList[POLICYNUM];

//申请内存使用的list
static NPAGED_LOOKASIDE_LIST    g_policyLookList;

//进程配置锁
static  KSPIN_LOCK  g_policyListlock = 0;

static BOOL g_IsClean = FALSE;

#define NF_TAG_POLICY 'CgTg'

//初始化配置
VOID InitPolicy()
{
	sl_init(&g_policyListlock);

	for (DWORD i = 0; i < POLICYNUM; i++)
	{
		PLIST_ENTRY pPolicyListEntry = &g_policyList[i];
		InitializeListHead(pPolicyListEntry);
	}
	
	ExInitializeNPagedLookasideList(
		&g_policyLookList,
		NULL,
		NULL,
		0,
		sizeof(NF_POLICY_LIST),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;
}

VOID FreePolicy()
{
	if (!g_IsClean)
		return;

	CleanAllPolicy();

	//释放List
	ExDeleteNPagedLookasideList(&g_policyLookList);
	KdPrint(("%s:%d(%s)[释放文件配置完成]\n", __FILE__, __LINE__, __FUNCTION__));
}

//清理所有配置
VOID CleanAllPolicy()
{
	KdPrint(("%s:%d(%s)[清理配置]\n", __FILE__, __LINE__, __FUNCTION__));

	if (!g_IsClean)
		return;

	for (DWORD i = 0; i < POLICYNUM; i++)
	{
		PNF_POLICY_LIST pQuery = NULL;
		KLOCK_QUEUE_HANDLE lh;
		int lock_status = 0;
		PLIST_ENTRY pPolicyListEntry = &g_policyList[i];
		try {
			sl_lock(&g_policyListlock, &lh);
			lock_status = 1;

			while (!IsListEmpty(pPolicyListEntry))
			{
				pQuery = (PNF_POLICY_LIST)RemoveHeadList(pPolicyListEntry);
				if (!pQuery)
				{
					break;
				}

				if (pQuery->data)
				{
					ExFreePoolWithTag(pQuery->data, NF_TAG_POLICY);
					pQuery->data = NULL;
				}

				sl_unlock(&lh);
				lock_status = 0;

				ExFreeToNPagedLookasideList(&g_policyLookList, pQuery);
				pQuery = NULL;
				sl_lock(&g_policyListlock, &lh);
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
	
}

VOID CleanPolicyByType(PPolicy cleanPolicy)
{
	if (!g_IsClean || !cleanPolicy)
		return;

	KdPrint(("%s:%d(%s)[清理类型配置]%d\n", __FILE__, __LINE__, __FUNCTION__, cleanPolicy->type));

	DWORD serialNum = cleanPolicy->type;
	if (serialNum > POLICY_FILE_LIST)
		return;

	PLIST_ENTRY pPolicyListEntry = &g_policyList[serialNum];
	if (IsListEmpty(pPolicyListEntry))
		return;
	
	PNF_POLICY_LIST pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;
	int lock_status = 0;
	try {

		sl_lock(&g_policyListlock, &lh);
		lock_status = 1;

		while (!IsListEmpty(pPolicyListEntry))
		{
			pQuery = (PNF_POLICY_LIST)RemoveHeadList(pPolicyListEntry);
			if (!pQuery)
			{
				break;
			}

			if (pQuery->data)
			{
				ExFreePoolWithTag(pQuery->data, NF_TAG_POLICY);
				pQuery->data = NULL;
			}
			if (pQuery->strData)
			{
				ExFreePoolWithTag(pQuery->strData, NF_TAG_POLICY);
				pQuery->strData = NULL;
			}

			sl_unlock(&lh);
			lock_status = 0;

			ExFreeToNPagedLookasideList(&g_policyLookList, pQuery);
			pQuery = NULL;
			sl_lock(&g_policyListlock, &lh);
			lock_status = 1;
		}

		sl_unlock(&lh);
		lock_status = 0;
	}
	finally {
		if (1 == lock_status)
			sl_unlock(&lh);
	}

	return;
}
//删除一项配置
VOID DeletePolicyList(PPolicy deletePolicy)
{
	if (!g_IsClean || !deletePolicy || deletePolicy->data[0] == '\0')
		return;

	DWORD serialNum = deletePolicy->type;
	if (serialNum > POLICY_FILE_LIST)
		return;

	PLIST_ENTRY pPolicyListEntry = &g_policyList[serialNum];
	if (IsListEmpty(pPolicyListEntry))
		return;

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_policyListlock, &lh);

	ANSI_STRING ansiData = {0};
	RtlInitAnsiString(&ansiData, deletePolicy->data);
	UNICODE_STRING unicodeData = { 0 };
	RtlAnsiStringToUnicodeString(&unicodeData, &ansiData, TRUE);

	PWCHAR pPolicyData = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, unicodeData.Length+sizeof(WCHAR), NF_TAG_POLICY);
	if (!pPolicyData)
	{
		RtlFreeUnicodeString(&unicodeData);
		sl_unlock(&lh);
		return;
	}
	RtlZeroMemory(pPolicyData, unicodeData.Length + sizeof(WCHAR));
	RtlCopyMemory(pPolicyData, unicodeData.Buffer, unicodeData.Length);

	RtlFreeUnicodeString(&unicodeData);

	LIST_ENTRY* p = NULL;
	for (p = pPolicyListEntry->Flink; p != pPolicyListEntry; p = p->Flink)
	{
		PNF_POLICY_LIST policyList = CONTAINING_RECORD(p, NF_POLICY_LIST, entry);
		if (!policyList)
			continue;

		if (wcscmp(policyList->data, pPolicyData) == 0)
		{ 
			RemoveEntryList(&policyList->entry);

			KdPrint(("%s:%d(%s)[删除配置]:%d,%S\n", __FILE__, __LINE__, __FUNCTION__, policyList->type, policyList->data));

			break;
		}
	}

	sl_unlock(&lh);
	ExFreePoolWithTag(pPolicyData,NF_TAG_POLICY);
	pPolicyData = NULL;

	PrintPolicyData();
}


//设置配置
NTSTATUS SetPolicy(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PPolicy pPolicyData = NULL;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		goto FINAL;

	PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (NULL == inputBuffer || inputBufferLength < sizeof(Policy))
	{
		status = STATUS_INVALID_PARAMETER;
		goto FINAL;
	}

	pPolicyData = ExAllocatePoolWithTag(NonPagedPool, sizeof(Policy), NF_TAG_POLICY);
	if (NULL == pPolicyData)
		goto FINAL;
	RtlZeroMemory(pPolicyData, sizeof(Policy));
	RtlCopyMemory(pPolicyData, inputBuffer, inputBufferLength);

	DWORD serialNum = pPolicyData->type;
	if (serialNum > POLICY_FILE_LIST)
		goto FINAL;

	if (pPolicyData->operation == CLR)
	{
		CleanPolicyByType(pPolicyData);
		goto FINAL;
	}
	else if (pPolicyData->operation == DEL)
	{
		DeletePolicyList(pPolicyData);
		goto FINAL;
	}

	//申请list内存
	PNF_POLICY_LIST pPolicyList = (PNF_POLICY_LIST)ExAllocateFromNPagedLookasideList(&g_policyLookList);
	//PNF_CONFIG_LIST configList = (PNF_CONFIG_LIST)ExAllocatePoolWithTag(NonPagedPool,sizeof(NF_CONFIG_LIST)); (&g_policyLookList);
	if (!pPolicyList)
	{
		status = STATUS_UNSUCCESSFUL;
		goto FINAL;
	}

	RtlZeroMemory(pPolicyList,sizeof(NF_POLICY_LIST));

	pPolicyList->type = serialNum;


	pPolicyList->strData = (LPSTR)ExAllocatePoolWithTag(NonPagedPool, sizeof(pPolicyData->data), NF_TAG_POLICY);
	if (!pPolicyList->strData)
	{
		status = STATUS_UNSUCCESSFUL;
		goto FINAL;
	}
	RtlZeroMemory(pPolicyList->strData, sizeof(pPolicyData->data));
	RtlCopyMemory(pPolicyList->strData, pPolicyData->data, sizeof(pPolicyData->data));


	ANSI_STRING ansiData = {0};
	RtlInitAnsiString(&ansiData, pPolicyData->data);
	UNICODE_STRING unicodeData = { 0 };
	RtlAnsiStringToUnicodeString(&unicodeData,&ansiData,TRUE);

	//申请保存配置数据的内存
	pPolicyList->data = (LPWCH)ExAllocatePoolWithTag(NonPagedPool, unicodeData.Length+sizeof(WCHAR), NF_TAG_POLICY);
	if (!pPolicyList->data)
	{
		status = STATUS_UNSUCCESSFUL;
		RtlFreeUnicodeString(&unicodeData);
		goto FINAL;
	}

	RtlZeroMemory(pPolicyList->data, unicodeData.Length+ sizeof(WCHAR));
	RtlCopyMemory(pPolicyList->data, unicodeData.Buffer, unicodeData.Length);

	RtlFreeUnicodeString(&unicodeData);

	PLIST_ENTRY pPolicyListEntry = &g_policyList[serialNum];
	//链表加入
	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_policyListlock, &lh);
	InsertHeadList(pPolicyListEntry, &pPolicyList->entry);
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s)[添加配置]type:%d,data:%S\n", __FILE__, __LINE__, __FUNCTION__,
		serialNum, pPolicyList->data));

	PrintPolicyData();

FINAL:
	if (pPolicyData)
	{
		ExFreePoolWithTag(pPolicyData, NF_TAG_POLICY);
		pPolicyData = NULL;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

//是否允许的数据
//白名单：不记录名单上行为，其他的都记录（TRUE）
//黑名单：只记录名单上行为，其他的不记录（FALSE）
BOOL IsAllowData(PolicyType_EM type,PVOID pData, BOOL isUnicode)
{
	BOOL ret = FALSE;
	LPWCH pPolicyData = NULL;

	BOOL isWhite = GetTypeConfig(Monitor_Mode);

	if (type > POLICY_FILE_LIST || pData == NULL)
	{
		goto FINAL;
	}
	
	if (isUnicode)
	{
		ULONG dataSize = wcslen((LPWCH)pData);
		if (dataSize == 0)
		{
			goto FINAL;
		}
		pPolicyData = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, (dataSize+1)*sizeof(WCHAR), NF_TAG_POLICY);
		if (!pPolicyData)
		{
			goto FINAL;
		}
		RtlZeroMemory(pPolicyData, (dataSize + 1) * sizeof(WCHAR));
		RtlCopyMemory(pPolicyData, pData, dataSize * sizeof(WCHAR));
	}
	else
	{
		if (((LPSTR)pData)[0] == '\0')
			goto FINAL;
	}

	//if (isUnicode)
	//	KdPrint(("进程名:%S\n", pPolicyData));
	//else
	//	KdPrint(("进程名:%s\n", (LPSTR)pData));

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_policyListlock, &lh);
	PLIST_ENTRY pPolicyListEntry = &g_policyList[type];
	if (IsListEmpty(pPolicyListEntry))
	{
		sl_unlock(&lh);
		goto FINAL;
	}

	PLIST_ENTRY p = NULL;
	for (p = pPolicyListEntry->Flink; p != pPolicyListEntry; p = p->Flink)
	{
		PNF_POLICY_LIST policyList = CONTAINING_RECORD(p, NF_POLICY_LIST, entry);

		if (isUnicode)
		{
			if (wcsstr(pPolicyData, policyList->data) != NULL)
			{
				ret = TRUE;
				break;
			}
		}
		else
		{
			if (strstr((LPSTR)pData, policyList->strData) != NULL)
			{
				ret = TRUE;
				break;
			}
		}

	}
	sl_unlock(&lh);
	
FINAL:
	if (isWhite)
	{
		ret = !ret;
	}

	if (pPolicyData)
	{
		ExFreePoolWithTag(pPolicyData, NF_TAG_POLICY);
		pPolicyData = NULL;
	}

	return ret;
}

//打印所有配置属性
VOID PrintPolicyData()
{
	for (DWORD i = 0; i < POLICYNUM; i++)
	{	
		KLOCK_QUEUE_HANDLE lh;
		sl_lock(&g_policyListlock, &lh);

		PLIST_ENTRY pPolicyListEntry = &g_policyList[i];
		if (IsListEmpty(pPolicyListEntry))
		{
			sl_unlock(&lh);
			continue;
		}

		PLIST_ENTRY p = NULL;
		for (p = pPolicyListEntry->Flink; p != pPolicyListEntry; p = p->Flink)
		{
			PNF_POLICY_LIST policyList = CONTAINING_RECORD(p, NF_POLICY_LIST, entry);
			KdPrint(("%s:%d(%s)[配置数据(%d)]:%d,%S\n", __FILE__, __LINE__, __FUNCTION__,
				i, policyList->type, policyList->data));
		}
		sl_unlock(&lh);
	}
}