#pragma once
#include <fltKernel.h>
#include <minwindef.h>

//总开关
typedef enum MonitorType
{
	//0-黑名单（记录行为） 1-白名单（不记录行为）
	Monitor_Mode = 0,
	//进程
	Monitor_Process = 100,
	//线程
	Monitor_Thread = 200,
	//文件
	Monitor_File = 300,
	//注册表
	Monitor_Registry = 400,
	//网络
	Monitor_Socket = 500,
	//USB
	Monitor_USB = 600,
	//模块加载
	Monitor_Image = 700,
	Monitor_Max = 1000,
} MonitorType_EM;

typedef ULONG Config[Monitor_Max];

//进程开关
typedef  enum MonitorTypeProcess
{
	//进程创建
	MT_ProcessCreate = Monitor_Process + 1,
	//进程退出
	MT_ProcessExit,
	//进程打开
	MT_ProcessOpen,
	//进程运行
	MT_ProcessStart,
} MonitorTypeProcess_EM;

//线程开关
typedef enum MonitorTypeThread
{
	//线程创建
	MT_ThreadCreate = Monitor_Thread + 1,
	//线程退出
	MT_ThreadExit,
	//线程打开
	MT_ThreadOpen,
	//线程运行
	MT_ThreadStart,
} MonitorTypeThread_EM;

//文件开关
typedef enum MonitorTypeFile
{
	//文件创建
	MT_FileCreate = Monitor_File + 1,
	//文件打开
	MT_FileOpen,
	//文件关闭 TODO
	MT_FileClose,
	//文件读取
	MT_FileRead,
	//文件写入
	MT_FileWrite,
	//文件删除 TODO
	MT_FileDelete,
} MonitorTypeFile_EM;

//注册表开关
typedef enum MonitorTypeRegistry
{
	//注册表创建
	MT_RegCreateKey = Monitor_Registry + 1,
	//注册表打开
	MT_RegOpenKey,
	//注册表删除项
	MT_RegDeleteKey,
	//注册表重命名
	MT_RenameKey,
	//注册表枚举
	MT_RegEnumKey,
	//注册表删除值
	MT_RegDeleteValue,
	//注册表设置值
	MT_RegSetValue,
	//注册表查询值
	MT_RegQueryValue,
} MonitorTypeRegistry_EM;

//网络开关
typedef enum MonitorTypeSocket
{
	//网络创建
	MT_SocketCreate = Monitor_Socket + 1,
	//网络绑定端口
	MT_SocketBind,
	//网路关闭
	MT_SocketClose,
	//网络连接
	MT_SocketConnect,
	//网络发送
	MT_SocketSend,
	//网络数据接收
	MT_SocketRecv,
	//服务端建立连接
	MT_SocketAccept,
} MonitorTypeSocket_EM;

//USB设备
typedef enum MonitorTypeUSB
{
	MT_USBArrival = Monitor_USB + 1,		//USB设备插入
	MT_USBRemoval,							//USB设备移除	
} MonitorTypeUSB_EM;

//开关配置
NTSTATUS SetConfig(PIRP irp, PIO_STACK_LOCATION irpSp);
//黑白名单配置
NTSTATUS SetWorkMode(PIRP irp, PIO_STACK_LOCATION irpSp);
BOOL GetTypeConfig(ULONG type);
