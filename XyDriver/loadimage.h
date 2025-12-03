#pragma once
#include <fltKernel.h>
#include <public.h>

typedef struct _LOADIMAGEINFO
{
	WCHARMAX imagePath;
	//线程id
	ULONG threadId;
	//进程创建时间
	LONGLONG createTime;
	ULONG_PTR imageSize;
}LOADIMAGEINFO,*PLOADIMAGEINFO;

//初始化模块加载模块
NTSTATUS LoadImageInit();
//清理模块加载模块
VOID CleanLoadImage();
//释放模块加载模块
VOID FreeLoadImage();

//加载模块回调
VOID LoadImageNotifyRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo);

//内存申请
PDEVBUFFER ImagePacketAllocate(int lens);
//释放内存
void ImagePacketFree(PDEVBUFFER packet);
//获取进程信息
PDEVDATA GetImageCtx();

//检测数据量
VOID CheckImageDataNum();


