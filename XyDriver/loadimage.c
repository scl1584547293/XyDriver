#include "loadimage.h"
#include <devctrl.h>
#include "policy.h"
#include "StackWalker.h"

static BOOL g_IsLoadImageInit = FALSE;

//申请内存的List
static NPAGED_LOOKASIDE_LIST g_loadImageList;
//进程数据
static DEVDATA g_loadImageData;
BOOL g_IsClean = FALSE;


#define NF_TAG_IMAGE 'IgTg'
#define NF_TAG_IMAGE_BUF 'IbTg'

//一条数据申请内存大小
#define IMAGE_ALLOCATESIZE sizeof(MonitorMsg)+sizeof(LOADIMAGEINFO)
#define IMAGE_DATAMAXNUM LIST_MAX_SIZE/IMAGE_ALLOCATESIZE


//初始化模块加载模块
NTSTATUS LoadImageInit()
{
	NTSTATUS status = STATUS_SUCCESS;

	sl_init(&g_loadImageData.lock);
	InitializeListHead(&g_loadImageData.pending);

	ExInitializeNPagedLookasideList(
		&g_loadImageList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;

	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [LoadImage]PsSetLoadImageNotifyRoutine err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));
		return status;
	}

	g_IsLoadImageInit = TRUE;
	return status;
}

//回调函数
VOID LoadImageNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName,_In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
	PMonitorMsg pImageMsg = NULL;

	if (!FullImageName || !GetTypeConfig(Monitor_Image))
		goto FINAL;

	pImageMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, IMAGE_ALLOCATESIZE, NF_TAG_IMAGE);
	if (pImageMsg == NULL)
	{
		KdPrint(("%s:%d(%s) [LoadImage]ExAllocatePoolWithTag PMonitorMsg err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}
	RtlZeroMemory(pImageMsg, IMAGE_ALLOCATESIZE);

	PLOADIMAGEINFO pLoadImageInfo = (PLOADIMAGEINFO)pImageMsg->data;
	if (!pLoadImageInfo)
		goto FINAL;

	pImageMsg->common.type = Monitor_Image;
	pImageMsg->common.pid = (DWORD)ProcessId;
	pLoadImageInfo->threadId = (DWORD)PsGetCurrentThread();

	GetCurrentTimeString(&pImageMsg->common.time);

	//根据进程id获取进程名
	GetProcessNameByPID((DWORD)ProcessId, pImageMsg->common.comm, sizeof(pImageMsg->common.comm), &pImageMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)ProcessId, &pLoadImageInfo->createTime);

	//模块路径
	RtlCopyMemory(pLoadImageInfo->imagePath, FullImageName->Buffer,sizeof(pLoadImageInfo->imagePath));
	//模块大小
	pLoadImageInfo->imageSize = ImageInfo->ImageSize;

	WCHARMAX processPath = { 0 };
	//根据进程id获取进程路径
	if (QueryProcessNamePath((DWORD)ProcessId, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pImageMsg->common.exe, processPath, sizeof(WCHARMAX));
		if (!IsAllowData(POLICY_EXE_LIST, pImageMsg->common.exe, TRUE))
		{
			goto FINAL;
		}
	}
	else
	{
		if (!IsAllowData(POLICY_EXE_LIST, pImageMsg->common.comm, FALSE))
		{
			goto FINAL;
		}
	}

	PDEVBUFFER pInfo = (PDEVBUFFER)ImagePacketAllocate(IMAGE_ALLOCATESIZE);
	if (!pInfo)
	{
		KdPrint(("%s:%d(%s) [LoadImage]ImagePacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		goto FINAL;
	}

	RtlCopyMemory(pInfo->dataBuffer, pImageMsg, IMAGE_ALLOCATESIZE);

	//检测数据量
	CheckImageDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_loadImageData.lock, &lh);
	InsertHeadList(&g_loadImageData.pending, &pInfo->pEntry);

	g_loadImageData.dataSize++;
	sl_unlock(&lh);

	//添加采集数据
	PushInfo(Monitor_Image);

FINAL:
	if (pImageMsg)
	{
		ExFreePoolWithTag(pImageMsg, NF_TAG_IMAGE);
		pImageMsg = NULL;
	}
	return;
}

//清理模块加载模块
VOID CleanLoadImage()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_loadImageData.lock, &lh);
		lock_status = 1;

		while (!IsListEmpty(&g_loadImageData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_loadImageData.pending);
			if (!pData)
				break;

			g_loadImageData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			ImagePacketFree(pData);
			pData = NULL;
			sl_lock(&g_loadImageData.lock, &lh);
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

//释放模块加载模块
VOID FreeLoadImage()
{
	if (!g_IsClean)
		return;

	CleanLoadImage();
	ExDeleteNPagedLookasideList(&g_loadImageList);

	if (g_IsLoadImageInit)
	{
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		g_IsLoadImageInit = FALSE;
	}
}

//内存申请
PDEVBUFFER ImagePacketAllocate(int lens)
{
	PDEVBUFFER pLoadImageBuf = NULL;
	if (lens <= 0)
		return pLoadImageBuf;

	pLoadImageBuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_loadImageList);
	if (!pLoadImageBuf)
		return pLoadImageBuf;

	RtlZeroMemory(pLoadImageBuf, sizeof(DEVBUFFER));

	pLoadImageBuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_IMAGE_BUF);
	if (!pLoadImageBuf->dataBuffer)
	{
		ExFreeToNPagedLookasideList(&g_loadImageList, pLoadImageBuf);
		pLoadImageBuf = NULL;
		return pLoadImageBuf;
	}
	pLoadImageBuf->dataLength = lens;
	RtlZeroMemory(pLoadImageBuf->dataBuffer, lens);

	return pLoadImageBuf;
}

//释放内存
void ImagePacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;

	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_IMAGE_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_loadImageList, packet);
}

//获取进程信息
PDEVDATA GetImageCtx()
{
	return &g_loadImageData;
}

//检测数据量
VOID CheckImageDataNum()
{
	if (g_loadImageData.dataSize > IMAGE_DATAMAXNUM)
	{
		CleanLoadImage();
	}
}
