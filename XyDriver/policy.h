#pragma once
#include <fltKernel.h>
#include "config.h"

//typedef enum PolicySerialNum
//{
//	SERIAL_INTERAL = 0,
//	SERIAL_PROCESS,
//	//SERIAL_THREAD,
//	SERIAL_FILE,
//	//SERIAL_REGISTRY,
//	//SERIAL_SOCKET,
//	//SERIAL_USB,
//	SERIAL_MAX
//}POLICY_SERIALNUM;

typedef enum PolicyOperation
{
	ADD = 1,
	DEL,
	CLR,
} POLICY_OPERATION_EM;

typedef enum _policy_type {
	POLICY_EXE_LIST,
	POLICY_FILE_LIST,
} PolicyType_EM;

typedef struct _Policy {
	PolicyType_EM type;                   //策略类型
	POLICY_OPERATION_EM operation;          //策略操作，添加、删除、清空
	UCHAR data[1024];                        //策略数据部分，比如进程路径或文件路径
} Policy,*PPolicy;

typedef struct _NF_POLICY_LIST
{
	LIST_ENTRY		entry;
	POLICY_OPERATION_EM type;
	LPWCH			data;
	//辅助数据
	LPSTR			strData;
} NF_POLICY_LIST, *PNF_POLICY_LIST;

//初始化配置
VOID InitPolicy();
//清理配置
VOID CleanAllPolicy();
//释放配置
VOID FreePolicy();
//清空一种类型数据
VOID CleanPolicyByType(PPolicy cleanPolicy);
//删除一项配置
VOID DeletePolicyList(PPolicy deletePolicy);
//设置进程配置
NTSTATUS SetPolicy(PIRP irp, PIO_STACK_LOCATION irpSp);
//是否允许的数据
BOOL IsAllowData(PolicyType_EM type, PVOID pData, BOOL isUnicode);
//打印所有配置属性
VOID PrintPolicyData();

