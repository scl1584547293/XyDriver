#include "register.h"
#include "process.h"
#include "devctrl.h"
#include "policy.h"

#define NF_TAG_REG 'RgTg'
#define NF_TAG_REG_BUF 'RbTg'

//一条数据申请内存大小
#define REGISTRY_ALLOCATESIZE sizeof(MonitorMsg) + sizeof(REGISTERINFO)
#define REGISTRY_DATAMAXNUM LIST_MAX_SIZE/REGISTRY_ALLOCATESIZE


LARGE_INTEGER	g_cookie;

//申请内存的List
static NPAGED_LOOKASIDE_LIST g_registerList;
//注册表数据
static DEVDATA g_regData;

static BOOL g_IsClean = FALSE;

//初始化注册表模块
NTSTATUS RegisterInit()
{
	sl_init(&g_regData.lock);
	InitializeListHead(&g_regData.pending);

	ExInitializeNPagedLookasideList(
		&g_registerList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;

	NTSTATUS status = STATUS_SUCCESS;
	status = CmRegisterCallback((PEX_CALLBACK_FUNCTION)RegistryObjectCallback, NULL, &g_cookie);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [Register]CmRegisterCallback err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		return status;
	}

	return status;
}

//清理注册表模块
VOID CleanRegister()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_regData.lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_regData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_regData.pending);
			if (!pData)
				break;
			
			g_regData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;

			RegisterPacketFree(pData);
			pData = NULL;
			sl_lock(&g_regData.lock, &lh);
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

//释放注册表模块
VOID FreeRegister()
{
	if (!g_IsClean)
		return;

	CleanRegister();
	ExDeleteNPagedLookasideList(&g_registerList);

	if (g_cookie.QuadPart > 0)
	{
		CmUnRegisterCallback(g_cookie);
	}
	return;
}


// 获取注册表完整路径
BOOL GetFullPath(PVOID pRegistryObject,LPWCH pRegistryPath, DWORD pathSize)
{
	PVOID lpObjectNameInfo = NULL;
	BOOL ret = FALSE;
	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		goto FINAL;
	}

	// 判断数据地址是否有效
	if ((FALSE == MmIsAddressValid(pRegistryObject)) ||
		(NULL == pRegistryObject))
	{
		//KdPrint(("%s:%d(%s) [Register]MmIsAddressValid err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	// 申请内存
	ULONG ulSize = 512;
	lpObjectNameInfo = ExAllocatePoolWithTag(NonPagedPool, ulSize,NF_TAG_REG);
	if (NULL == lpObjectNameInfo)
	{
		//KdPrint(("%s:%d(%s) [Register]ExAllocatePool err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(lpObjectNameInfo, ulSize);

	// 获取注册表路径
	ULONG ulRetLen = 0;
	NTSTATUS status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)lpObjectNameInfo, ulSize, &ulRetLen);
	if (!NT_SUCCESS(status))
	{
		//KdPrint(("%s:%d(%s) [Register]ObQueryNameString err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	PUNICODE_STRING pObjectName = (PUNICODE_STRING)lpObjectNameInfo;
	if (!pObjectName)
		goto FINAL;

	if (pObjectName->Length > pathSize)
	{
		RtlCopyMemory(pRegistryPath, pObjectName->Buffer, pathSize);
	}
	else
	{
		RtlCopyMemory(pRegistryPath, pObjectName->Buffer, pObjectName->Length);
	}

	ret = TRUE;
FINAL:
	if (lpObjectNameInfo)
	{
		// 释放内存
		ExFreePoolWithTag(lpObjectNameInfo, NF_TAG_REG);
		lpObjectNameInfo = NULL;
	}

	return TRUE;
}

//注册表回调函数
NTSTATUS RegistryObjectCallback(IN PVOID pCallbackContext,IN REG_NOTIFY_CLASS notifyClass,IN PVOID pArgument2)
{
	PMonitorMsg pRegisterMsg = NULL;
	UNICODE_STRING	RegPath = {0};

	if (!CheckRegConfig(notifyClass) || KeGetCurrentIrql() > APC_LEVEL || PsGetCurrentProcessId() == 0 || 
		PsGetCurrentProcessId() == PsGetProcessId(PsInitialSystemProcess) || NULL == pArgument2)
		goto FINAL;
	
	//RegPath.Length = 0;
	//RegPath.MaximumLength = 1024 * sizeof(WCHAR);
	//RegPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength,NF_TAG_REG);
	//if (NULL == RegPath.Buffer)
	//{
	//	KdPrint(("%s:%d(%s) [Register]ExAllocatePool RegPath err\n", __FILE__, __LINE__, __FUNCTION__));
	//	goto FINAL;
	//}
	//RtlZeroMemory(RegPath.Buffer, RegPath.MaximumLength);

	HANDLE processId = PsGetCurrentProcessId();
	HANDLE threadId = PsGetCurrentThreadId();

	//if (!IsAllowProcess(processPath))
	//	goto FINAL;


	//WCHAR linkProcessPath[MAX_PATH] = { 0 };
	//PWSTR processPath = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, 255 * sizeof(WCHAR), REGPATH_TAG);
	//PWSTR linkProcessPath = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, 255 * sizeof(WCHAR), REGPATH_TAG);

	//ULONG bSize = 0;
	//status = GetProcessImagePathByProcessId(processId, processPath, MAX_PATH, &bSize);
	//if (!NT_SUCCESS(status))
	//{
	//	//if (status == STATUS_INFO_LENGTH_MISMATCH)
	//	//{
	//	//	ExFreePoolWithTag(processPath, REGPATH_TAG);
	//	//	ExFreePoolWithTag(linkProcessPath, REGPATH_TAG);
	//	//	processPath = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, bSize * sizeof(WCHAR), REGPATH_TAG);
	//	//	linkProcessPath = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, bSize * sizeof(WCHAR), REGPATH_TAG);
	//	//	status = GetProcessImagePathByProcessId(processId, processPath, bSize, &bSize);
	//	//	if (!NT_SUCCESS(status))
	//	//	{
	//	//		goto FINAL;
	//	//	}
	//	//}
	//	//else
	//	{
	//		goto FINAL;
	//	}
	//}

	//if (!GetNTLinkName(processPath, linkProcessPath))
	//{
	//	KdPrint(("%s:%d [Register]GetNTLinkName RegPath err\n", __FILE__, __LINE__));
	//	goto FINAL;
	//}
	//KIRQL oldIrql = PASSIVE_LEVEL;
	////提升IRQL级别
	//if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	//{
	//	KeRaiseIrql(PASSIVE_LEVEL, &oldIrql);
	//}
	//RtlStringCbCopyNW(linkProcessPath, sMAX_PATH, processPath, MAX_PATH);
	////恢复
	//if (oldIrql != PASSIVE_LEVEL)
	//{
	//	KeLowerIrql(oldIrql);
	//}

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(REGISTERINFO);

	pRegisterMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, REGISTRY_ALLOCATESIZE,NF_TAG_REG);
	if (!pRegisterMsg)
		goto FINAL;
	RtlZeroMemory(pRegisterMsg, REGISTRY_ALLOCATESIZE);

	PREGISTERINFO pRegisterinfo = (PREGISTERINFO)pRegisterMsg->data;
	if (!pRegisterinfo)
		goto FINAL;

	pRegisterMsg->common.type = Monitor_Registry;

	//根据进程id获取进程名
	GetProcessNameByPID((DWORD)processId, pRegisterMsg->common.comm, sizeof(pRegisterMsg->common.comm),&pRegisterMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)processId, &pRegisterinfo->createTime);

	WCHARMAX processPath = { 0 };
	//根据进程id获取进程路径
	if (QueryProcessNamePath((DWORD)processId, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pRegisterMsg->common.exe, processPath, sizeof(WCHARMAX));
		if (!IsAllowData(POLICY_EXE_LIST, pRegisterMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pRegisterMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	pRegisterMsg->common.pid = (DWORD)processId;
	pRegisterinfo->threadId = (DWORD)threadId;

	GetCurrentTimeString(&pRegisterMsg->common.time);

	BOOL isHaveData = FALSE;
	switch (notifyClass)
	{
		//打开注册表之前
	case RegNtPreOpenKeyEx:
	case RegNtPreOpenKey:
	{
		pRegisterinfo->opearType = MT_RegOpenKey;
//#ifdef WINXP
		PREG_OPEN_KEY_INFORMATION openKeyInfo = (PREG_OPEN_KEY_INFORMATION)pArgument2;
//#else
//		PREG_OPEN_KEY_INFORMATION_V1 openKeyInfo = (PREG_OPEN_KEY_INFORMATION_V1)pArgument2;
//#endif
		if (openKeyInfo->RootObject)
		{
			//获取注册表路径
			GetFullPath(openKeyInfo->RootObject, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}
		
		//pRegisterinfo->object = openKeyInfo->RootObject;
		if (openKeyInfo->CompleteName && openKeyInfo->CompleteName->Buffer && (openKeyInfo->CompleteName->Length < sizeof(WCHARMAX)))
			RtlCopyMemory(pRegisterinfo->name,openKeyInfo->CompleteName->Buffer, openKeyInfo->CompleteName->Length);
		KdPrint(("打开键"));
		isHaveData = TRUE;
		
		break;
	}
		//创建注册表之前
	case RegNtPreCreateKeyEx:
	case RegNtPreCreateKey:
	{
		pRegisterinfo->opearType = MT_RegCreateKey;

#ifdef WINXP
		PREG_OPEN_KEY_INFORMATION createKey = (PREG_OPEN_KEY_INFORMATION)pArgument2;
#else
		PREG_OPEN_KEY_INFORMATION_V1 createKey = (PREG_OPEN_KEY_INFORMATION_V1)pArgument2;
		if (createKey->RootObject)
		{
			//获取注册表路径
			GetFullPath(createKey->RootObject, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}
#endif

		if (createKey->CompleteName && createKey->CompleteName->Buffer && (createKey->CompleteName->Length < sizeof(WCHARMAX)))
			RtlCopyMemory(pRegisterinfo->name, createKey->CompleteName->Buffer, createKey->CompleteName->Length);
		isHaveData = TRUE;
		KdPrint(("创建键"));
		break;
	}	
	//设置键值
	case RegNtPreSetValueKey:
	{
		pRegisterinfo->opearType = MT_RegSetValue;
		PREG_SET_VALUE_KEY_INFORMATION regSetValueinfo = (PREG_SET_VALUE_KEY_INFORMATION)pArgument2;
		//if (GetFullPath(&RegPath, ((PREG_SET_VALUE_KEY_INFORMATION)pArgument2)->Object))
		if (regSetValueinfo->Object)
		{
			//获取注册表路径
			GetFullPath(regSetValueinfo->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}
	
		//pRegisterinfo->object = regSetValueinfo->Object;
		pRegisterinfo->type = regSetValueinfo->Type;

		if (regSetValueinfo->ValueName && regSetValueinfo->ValueName->Buffer && (regSetValueinfo->ValueName->Length < sizeof(WCHARMAX)))
			RtlCopyMemory(pRegisterinfo->name, regSetValueinfo->ValueName->Buffer, regSetValueinfo->ValueName->Length);
		if (regSetValueinfo->Data && (regSetValueinfo->DataSize < MAX_PATH))
			RtlCopyMemory(pRegisterinfo->setData,regSetValueinfo->Data, regSetValueinfo->DataSize);

		KdPrint(("设置键值"));
		isHaveData = TRUE;
		
		break;
	}	
		//删除键值（windows server 2003以上）
	case RegNtDeleteValueKey:
	{
		pRegisterinfo->opearType = MT_RegDeleteValue;
		PREG_DELETE_VALUE_KEY_INFORMATION deleteValueKeyInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)pArgument2;
		//if (GetFullPath(&RegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)pArgument2)->Object))
		if (deleteValueKeyInfo->Object)
		{
			//获取注册表路径
			GetFullPath(deleteValueKeyInfo->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}
	
		//pRegisterinfo->object = deleteValueKeyInfo->Object;
		if (deleteValueKeyInfo->ValueName && deleteValueKeyInfo->ValueName->Buffer && (deleteValueKeyInfo->ValueName->Length < sizeof(WCHARMAX)))
			RtlCopyMemory(pRegisterinfo->name,deleteValueKeyInfo->ValueName->Buffer, deleteValueKeyInfo->ValueName->Length);
		KdPrint(("删除键值"));
		isHaveData = TRUE;
		
		break;
	}		
		//删除键之后
	case RegNtPostDeleteKey:
	case RegNtDeleteKey:
	{
		pRegisterinfo->opearType = MT_RegDeleteKey;
		PREG_DELETE_KEY_INFORMATION deleteKeyInfo = (PREG_DELETE_KEY_INFORMATION)pArgument2;
		if (deleteKeyInfo->Object)
		{
			//获取注册表路径
			GetFullPath(deleteKeyInfo->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}


		//pRegisterinfo->object = ((PREG_DELETE_KEY_INFORMATION)pArgument2)->Object;
		KdPrint(("删除键项"));
		isHaveData = TRUE;
		
		break;
	}
	//重命名
	case RegNtRenameKey:
	{
		pRegisterinfo->opearType = MT_RenameKey;
		PREG_RENAME_KEY_INFORMATION regRenameinfo = (PREG_RENAME_KEY_INFORMATION)pArgument2;
		if (regRenameinfo->Object)
		{
			//获取注册表路径
			GetFullPath(regRenameinfo->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}
	
		//pRegisterinfo->object = regRenameinfo->Object;
		if (regRenameinfo->NewName && regRenameinfo->NewName->Buffer && (regRenameinfo->NewName->Length < sizeof(WCHARMAX)))
			RtlCopyMemory(pRegisterinfo->name, regRenameinfo->NewName->Buffer, regRenameinfo->NewName->Length);
		KdPrint(("重命名键"));
		isHaveData = TRUE;
		
		break;
	}
		//枚举项
	case RegNtEnumerateKey:
	{
		pRegisterinfo->opearType = MT_RegEnumKey;
		PREG_ENUMERATE_KEY_INFORMATION enumKeyInfo = (PREG_ENUMERATE_KEY_INFORMATION)pArgument2;
		//if (GetFullPath(&RegPath, ((PREG_ENUMERATE_KEY_INFORMATION)pArgument2)->Object))
		if (enumKeyInfo->Object)
		{
			//获取注册表路径
			GetFullPath(enumKeyInfo->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}

		//pRegisterinfo->object = enumKeyInfo->Object;
		pRegisterinfo->index = enumKeyInfo->Index;

		if (enumKeyInfo->KeyInformation)
		{
			switch (enumKeyInfo->KeyInformationClass)
			{
			case KeyBasicInformation:
			{
				PKEY_BASIC_INFORMATION  pKeyValue = (PKEY_BASIC_INFORMATION)enumKeyInfo->KeyInformation;

				if (pKeyValue->NameLength < sizeof(WCHARMAX))
					RtlCopyMemory(pRegisterinfo->name, pKeyValue->Name, pKeyValue->NameLength);

				break;
			}
			case KeyNodeInformation:
			{
				PKEY_NODE_INFORMATION  pKeyValue = (PKEY_NODE_INFORMATION)enumKeyInfo->KeyInformation;

				if (pKeyValue->NameLength < sizeof(WCHARMAX))
					RtlCopyMemory(pRegisterinfo->name, pKeyValue->Name, pKeyValue->NameLength);

				break;
			}
			case KeyNameInformation:
			{
				PKEY_NAME_INFORMATION  pKeyValue = (PKEY_NAME_INFORMATION)enumKeyInfo->KeyInformation;

				if (pKeyValue->NameLength < sizeof(WCHARMAX))
					RtlCopyMemory(pRegisterinfo->name, pKeyValue->Name, pKeyValue->NameLength);

				break;
			}
			}
		}

		//pRegisterinfo->keyInformationClass = enumKeyInfo->KeyInformationClass;
		//KdPrint(("枚举项:索引:%d,缓冲区大小:%d",enumKeyInfo->Index,enumKeyInfo->Length));
		isHaveData = TRUE;
		
		KdPrint(("枚举项"));
		break;
	}
		//枚举键
	//case RegNtEnumerateValueKey:
	//{
	//	PREG_ENUMERATE_VALUE_KEY_INFORMATION enumValueKeyInfo = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)pArgument2;
	//	//if (GetFullPath(&RegPath, ((PREG_ENUMERATE_VALUE_KEY_INFORMATION)pArgument2)->Object))
	//	if (!enumValueKeyInfo->Object)
	//		break;

	//	//获取注册表路径
	//	GetFullPath(enumValueKeyInfo->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
	//	
	//	//pRegisterinfo->object = enumValueKeyInfo->Object;
	//	pRegisterinfo->index = enumValueKeyInfo->Index;
	//	pRegisterinfo->keyInformationClass = enumValueKeyInfo->KeyValueInformationClass;
	//	//KdPrint(("枚举键:索引:%d,缓冲区大小:%d",enumValueKeyInfo->Index,enumValueKeyInfo->Length));
	//	isHaveData = TRUE;
	//	
	//	break;
	//}
		//查询项
	//case RegNtQueryKey:
	//{
	//	//pRegisterinfo->opearType = MT_RegEnumKey;
	//	PREG_QUERY_KEY_INFORMATION queryKey = (PREG_QUERY_KEY_INFORMATION)pArgument2;
	//	//if (GetFullPath(&RegPath, ((PREG_QUERY_KEY_INFORMATION)pArgument2)->Object))
	//	if (queryKey->Object)
	//		break;

	//	//获取注册表路径
	//	GetFullPath(queryKey->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
	//	
	//	//pRegisterinfo->object = queryKey->Object;
	//	pRegisterinfo->keyInformationClass = queryKey->KeyInformationClass;
	//	//KdPrint(("查询项:,缓冲区大小:%d",queryKey->Length));
	//	isHaveData = TRUE;
	//	
	//	break;
	//}
		//查询键
	case RegNtPostQueryValueKey:
#ifdef WINXP
	//xp
	case RegNtQueryValueKey:
#endif
	{
		pRegisterinfo->opearType = MT_RegQueryValue;
		PREG_QUERY_VALUE_KEY_INFORMATION queryValuKey = (PREG_QUERY_VALUE_KEY_INFORMATION)pArgument2;

		//if (GetFullPath(&RegPath, ((PREG_QUERY_VALUE_KEY_INFORMATION)pArgument2)->Object))
		if (queryValuKey->Object)
		{
			//获取注册表路径
			GetFullPath(queryValuKey->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
		}

#ifndef WINXP
		switch (queryValuKey->KeyValueInformationClass)
		{
		case KeyValueBasicInformation:
		{
			PKEY_VALUE_BASIC_INFORMATION pKeyValue = (PKEY_VALUE_BASIC_INFORMATION)queryValuKey->KeyValueInformation;

			if (pKeyValue->NameLength < sizeof(WCHARMAX))
				RtlCopyMemory(pRegisterinfo->name, pKeyValue->Name, pKeyValue->NameLength);

			break;
		}		
		case KeyValueFullInformation:
		{
			PKEY_VALUE_FULL_INFORMATION pKeyValue = (PKEY_VALUE_FULL_INFORMATION)queryValuKey->KeyValueInformation;

			if (pKeyValue->NameLength < sizeof(WCHARMAX))
				RtlCopyMemory(pRegisterinfo->name, pKeyValue->Name, pKeyValue->NameLength);

			break;
		}		
		}
#endif

		//pRegisterinfo->object = queryValuKey->Object;
		//pRegisterinfo->keyInformationClass = queryValuKey->KeyValueInformationClass;

		//if (queryValuKey->ValueName && queryValuKey->ValueName->Buffer && (queryValuKey->ValueName->Length < sizeof(WCHARMAX)))
		//	RtlCopyMemory(pRegisterinfo->name,  queryValuKey->ValueName->Buffer, queryValuKey->ValueName->Length);

		//KdPrint(("查询键:[%S],缓冲区大小:%d", pRegisterinfo->name,queryValuKey->Length));
		isHaveData = TRUE;
		
		KdPrint(("查询键"));
		break;
	}
//#endif
		//关闭
	//case RegNtKeyHandleClose:
	//{
	//	//pRegisterinfo->opearType = MT_RegQueryValue;
	//	PREG_KEY_HANDLE_CLOSE_INFORMATION handleClose = (PREG_KEY_HANDLE_CLOSE_INFORMATION)pArgument2;
	//
	//	if (handleClose->Object)
	//		break;

	//	//获取注册表路径
	//	GetFullPath(handleClose->Object, pRegisterinfo->object, sizeof(pRegisterinfo->object));
	//	{
	//		//pRegisterinfo->object = ((PREG_KEY_HANDLE_CLOSE_INFORMATION)pArgument2)->Object;
	//		//KdPrint(("关闭注册表"));
	//		isHaveData = TRUE;
	//	}
	//	break;
	//}
	}

	if (!isHaveData)
		goto FINAL;

	
	PDEVBUFFER pRegbuf = (PDEVBUFFER)RegisterPacketAllocate(REGISTRY_ALLOCATESIZE);
	if (!pRegbuf)
	{
		//KdPrint(("%s:%d(%s) Register_PacketAllocate error\n",__FILE__,__LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pRegbuf->dataBuffer, pRegisterMsg, REGISTRY_ALLOCATESIZE);

	//检测数据量
	CheckRegistryDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_regData.lock, &lh);
	InsertHeadList(&g_regData.pending, &pRegbuf->pEntry);

	g_regData.dataSize++;
	sl_unlock(&lh);

	PushInfo(Monitor_Registry);

	KdPrint(("[Reg]进程名:%s,进程路径:%S,进程id:%d,线程id:%d\n", 
		pRegisterMsg->common.comm, pRegisterMsg->common.exe, processId,threadId));

	//拒绝访问
	//status = STATUS_ACCESS_DENIED;

FINAL:
	//if (RegPath.Buffer != NULL)
	//{
	//	ExFreePoolWithTag(RegPath.Buffer, NF_TAG_REG);
	//	RegPath.Buffer = NULL;
	//}

	if (pRegisterMsg)
	{
		ExFreePoolWithTag(pRegisterMsg,NF_TAG_REG);
		pRegisterMsg = NULL;
	}

	return STATUS_SUCCESS;
}

//从List中申请内存
PDEVBUFFER RegisterPacketAllocate(int lens)
{
	PDEVBUFFER pRegbuf = NULL;
	if (lens <= 0)
		return pRegbuf;
	
	pRegbuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_registerList);
	if (!pRegbuf)
		return pRegbuf;

	RtlZeroMemory(pRegbuf, sizeof(DEVBUFFER));

	pRegbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_REG_BUF);
	if (!pRegbuf->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_registerList, pRegbuf);
		pRegbuf = NULL;
		return pRegbuf;
	}
	pRegbuf->dataLength = lens;
	RtlZeroMemory(pRegbuf->dataBuffer, lens);
	
	return pRegbuf;
}

//释放内存
void RegisterPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;
	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_REG_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_registerList, packet);
}

//获取存储数据信息
PDEVDATA GetRegisterCtx()
{
	return &g_regData;
}

//检测数据量
VOID CheckRegistryDataNum()
{
	if (g_regData.dataSize > REGISTRY_DATAMAXNUM)
	{
		CleanRegister();

		//KLOCK_QUEUE_HANDLE lh;
		//sl_lock(&g_regData.lock, &lh);
		//g_regData.dataSize = 0;
		//sl_unlock(&lh);
	}
}

BOOL CheckRegConfig(REG_NOTIFY_CLASS notifyClass)
{
	switch (notifyClass)
	{
		//打开注册表之前
	case RegNtPreOpenKeyEx:
	case RegNtPreOpenKey:
		return GetTypeConfig(MT_RegOpenKey);
		//创建注册表之前
	case RegNtPreCreateKeyEx:
	case RegNtPreCreateKey:
		return GetTypeConfig(MT_RegCreateKey);
	case RegNtPreSetValueKey:
		return GetTypeConfig(MT_RegSetValue);
		//删除键值（windows server 2003以上）
	case RegNtDeleteValueKey:
		return GetTypeConfig(MT_RegDeleteValue);
		//删除项之后
	case RegNtPostDeleteKey:
	case RegNtDeleteKey:
		return GetTypeConfig(MT_RegDeleteKey);
		//重命名
	case RegNtRenameKey:
	case RegNtPostRenameKey:
		return GetTypeConfig(MT_RenameKey);
		//枚举项
	case RegNtEnumerateKey:
		return GetTypeConfig(MT_RegEnumKey);
		//查询项
#ifdef WINXP
	case RegNtQueryValueKey:
#endif
	case RegNtPostQueryValueKey:
		return GetTypeConfig(MT_RegQueryValue);
		//枚举键
	case RegNtEnumerateValueKey:
		//查询键
	case RegNtQueryKey:
		//关闭
	case RegNtKeyHandleClose:
		return FALSE;
	default:
		return FALSE;
	}

}