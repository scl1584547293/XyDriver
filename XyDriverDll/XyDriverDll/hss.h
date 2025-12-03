#ifndef _HSS_H_
#define _HSS_H_

#ifdef _WIN32
#include <Windows.h>
#else
#include <stdlib.h>
#include <stdio.h>

typedef unsigned int ULONG;
typedef ULONG *PULONG;
typedef char *LPSTR;

#define _In_
#define _Out_

#endif

#define SUCCESS                           0 //成功
#define ERROR_DRIVER_FILE_NOT_EXIST      -1 //驱动文件不存在
#define ERROR_DRIVER_NOT_LOADED          -2 //驱动未加载
#define ERROR_DRIVER_INSTALL             -3 //驱动安装失败
#define ERROR_DRIVER_UNINSTALL           -4 //驱动卸载失败
#define ERROR_DRIVER_START               -5 //驱动启动失败
#define ERROR_DRIVER_STOP                -6 //驱动停止失败
#define ERROR_DRIVER_OPEN                -7 //打开驱动设备或驱动文件失败
#define ERROR_DRIVER_SEND                -8 //发送通信指令失败
#define ERROR_DRIVER_READ                -9 //获取数据失败
#define ERROR_INVALID_VALUE              -10 //无效的参数
#define ERROR_MEMORY		             -11 //内存错误
//#define ERROR_ANALYSISJSON				 -12 //解析json错误

//windows错误码
#define ERROR_WIN_OPENSCMANAGER		-100	//打开资源管理器失败
#define ERROR_WIN_OPENSERVICE		-101	//打开服务失败
#define ERROR_WIN_CREATESERVICE		-102	//创建服务失败
#define ERROR_WIN_WRITEREGISTRY		-103	//写入注册表失败
#define ERROR_WIN_DELETESERVICE		-104	//删除服务失败


#define POLICY_DATA_LEN					1024

typedef enum MonitorType
{
	Monitor_Mode 		= 0,				//工作模式，1 白名单，0 黑名单，通过SetWorkMode设置，默认黑名单模式
	Monitor_Process 	= 100,				//进程总开关，通过SetConfig设置，如果关闭，所有进程行为均不记录
	Monitor_Thread 		= 200,				//线程总开关，通过SetConfig设置，如果关闭，所有线程行为均不记录
	Monitor_File 		= 300,				//文件总开关，通过SetConfig设置，如果关闭，所有文件行为均不记录
	Monitor_Registry 	= 400,				//注册表总开关，通过SetConfig设置，如果关闭，所有注册表行为均不记录
	Monitor_Socket 		= 500,				//socket总开关，通过SetConfig设置，如果关闭，所有socket行为均不记录
	Monitor_USB 		= 600,				//USB设备总开关，通过SetConfig设置，如果关闭，所有USB设备行为均不记录
	Monitor_Image		= 700,				//模块记载开关，通过SetConfig设置，如果关闭，所有模块加载行为均不记录
	Monitor_Max 		= 1000,				//上限
} MonitorType_EM;

//配置行为开关，不同的数组下标代表不同的开关项，参考MonitorType_EM定义和后续的子类型定义
typedef ULONG Config[Monitor_Max]; 

//进程
typedef  enum MonitorTypeProcess
{	
	MT_ProcessCreate = Monitor_Process + 1,	   	//进程创建	
	MT_ProcessExit,                            	//进程退出	
	MT_ProcessOpen,								//进程打开	
	MT_ProcessStart,							//进程启动
} MonitorTypeProcess_EM;

//线程
typedef enum MonitorTypeThread
{	
	MT_ThreadCreate = Monitor_Thread + 1,		//线程创建	
	MT_ThreadExit,								//线程退出	
	MT_ThreadOpen,								//线程打开	
	MT_ThreadStart,								//线程启动
} MonitorTypeThread_EM;

//文件
typedef enum MonitorTypeFile
{	
	MT_FileCreate = Monitor_File + 1,			//文件创建	
	MT_FileOpen,								//文件打开	
	MT_FileClose,								//文件关闭	
	MT_FileRead,								//文件读取	
	MT_FileWrite,								//文件写入	
	MT_FileDelete,								//文件删除
} MonitorTypeFile_EM;

//注册表
typedef enum MonitorTypeRegistry
{	
	MT_RegCreateKey = Monitor_Registry + 1,		//注册表创建	
	MT_RegOpenKey,								//注册表打开	
	MT_RegDeleteKey,							//注册表删除项	
	MT_RenameKey,								//注册表重命名	
	MT_RegEnumKey,								//注册表枚举	
	MT_RegDeleteValue,							//注册表删除值	
	MT_RegSetValue,								//注册表设置值	
	MT_RegQueryValue,							//注册表查询值
} MonitorTypeRegistry_EM;

//网络
typedef enum MonitorTypeSocket
{	
	MT_SocketCreate = Monitor_Socket + 1,		//网络创建
	MT_SocketBind,								//网络绑定端口	
	MT_SocketClose,								//网路关闭	
	MT_SocketConnect,							//发起连接	
	MT_SocketSend,								//发送数据	
	MT_SocketRecv,								//接收数据	
	MT_SocketAccept,							//接收连接	
} MonitorTypeSocket_EM;

//USB设备
typedef enum MonitorTypeUSB
{	
	MT_USBArrival = Monitor_USB + 1,		//USB设备插入
	MT_USBRemoval,							//USB设备移除	
} MonitorTypeUSB_EM;

typedef enum PolicyOperation
{
	ADD = 1,
	DEL,
	CLR,
	PRINT,
} PolicyOperation_EM;

typedef enum _policy_type {
    POLICY_EXE_LIST,
    POLICY_FILE_LIST,
} PolicyType_EM;

//策略
typedef struct _policy {
    PolicyType_EM       type;
    PolicyOperation_EM  operation;
	unsigned char 		data[POLICY_DATA_LEN];
} policy_t, Policy, *PPolicy;

typedef struct _monitor_msg_common {
	MonitorType_EM type;      //行为总类型
	int uid;                  //用户ID
	char exe[512];            //进程可执行文件（windows下转为wchar）
	int pid;                  //进程ID
	int ppid;                 //父进程ID
	int pgid;                 //进程组ID
	int tgid;                 //任务组ID
	char comm[32];            //进程名
	long long timestamp;	  //unix时间戳，单位秒
} monitor_msg_common_t, MonitorMsgCommon, *PMonitorMsgCommon;

typedef struct _monitor_msg {
	MonitorMsgCommon common; 	//公共部分
	char *data;              	//数据部分
} monitor_msg_t, MonitorMsg, *PMonitorMsg;

//工作模式
typedef enum _work_mode {
    BLACK,
    WHITE,
} WorkMode_EM;

#ifdef _WIN32

typedef WCHAR WCHARMAX[255];

//进程数据结构
typedef struct _PROCESSINFO
{
	MonitorTypeProcess_EM processType;
	//线程id
	ULONG threadId;
	ULONG pThreadId;
	//父进程路径
	WCHARMAX parenPath;
	//进程命令行
	WCHARMAX commandLine;
	//进程创建时间
	LONGLONG createTime;
}PROCESSINFO, *PPROCESSINFO;

//线程数据结构
typedef struct _THREADINFO
{
	//创建/销毁线程
	MonitorTypeThread_EM threadType;
	//线程id
	ULONG threadId;
	//进程创建时间
	LONGLONG createTime;
}THREADINFO, *PTHREADINFO;

//注册表数据结构
typedef struct _REGISTERINFO
{
	//
	MonitorTypeRegistry_EM opearType;
	//线程id
	ULONG threadId;
	//操作类型
	ULONG type;
	//注册表路径
	WCHARMAX object;
	//
	ULONG keyInformationClass;
	//是否64位
	ULONG wow64Flags;
	//索引
	ULONG index;
	//注册表项名
	WCHARMAX name;
	//修改数据
	char setData[MAX_PATH];
	//数据长度
	ULONG dataSize;
	//进程创建时间
	LONGLONG createTime;
}REGISTERINFO, *PREGISTERINFO;

//文件数据结构
typedef struct _FILEINFO
{
	//文件操作类型
	MonitorTypeFile_EM type;
	//线程id
	ULONG threadId;
	//文件名
	WCHARMAX fileName;
	//文件路径
	WCHARMAX filePath;
	//重命名后名字
	WCHARMAX rename;
	//进程创建时间
	LONGLONG createTime;
	//文件创建时间
	LONGLONG fileCreateTime;
}FILEINFO, *PFILEINFO;

//网络数据结构
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

//设备热插拔数据结构
typedef struct _HOTPLUGINFO
{
	MonitorTypeUSB_EM type;
	//线程id
	ULONG threadId;
	//设备符号链接的名称
	WCHARMAX symbolicLinkName;
	//设备接口的类
	GUID interfaceClassGuid;
	//进程创建时间
	LONGLONG createTime;
}HOTPLUGINFO, *PHOTPLUGINFO;

typedef struct _LOADIMAGEINFO
{
	WCHARMAX imagePath;
	//线程id
	ULONG threadId;
	//进程创建时间
	LONGLONG createTime;
	ULONG_PTR imageSize;
}LOADIMAGEINFO, *PLOADIMAGEINFO;
#else

//进程数据结构
typedef struct _PROCESSINFO
{
	MonitorTypeProcess_EM type;
	char pwd[1024];
} process_info_t, PROCESSINFO, *PPROCESSINFO;

//文件数据结构
typedef struct _FILEINFO
{
	MonitorTypeFile_EM type;
	char file_path[1024];	
} file_info_t, FILEINFO, *PFILEINFO;

//USB设备数据结构
typedef struct _USBINFO
{
	MonitorTypeUSB_EM type;	//类型
	char product[64];		//产品名
	char manufacturer[64];	//厂商名
	char serial[64];		//序列号
} usb_info_t, USBINFO, *PUSBINFO;

typedef struct _SOCKET_CREATE
{
	int family;
	int type;
	int protocol;
} SOCKETCREATE, *PSOCKETCREATE;

typedef struct _SOCKET
{
	int	type;
	char sip[64];
	int sport;
	char dip[64];
	int dport;
} SOCKET, *PSOCKET;

//网络数据结构
typedef struct _SOCKETINFO
{
	MonitorTypeSocket_EM type;
	union {
		SOCKETCREATE 	create;
		SOCKET			socket;
	} data;
} socket_info_t, SOCKETINFO, *PSOCKETINFO;

#endif


#ifdef _WIN32
#define STDCALL __stdcall
#else
#define STDCALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

//加载驱动
ULONG STDCALL LoadDriver(_In_ LPSTR pDriverPath);

//卸载驱动
ULONG STDCALL UnloadDriver();

//设置配置
ULONG STDCALL SetConfig(_In_ Config *pConfig);

//配置策略
ULONG STDCALL SetPolicy(_In_ PPolicy pPolicy);

//设置工作模式
ULONG STDCALL SetWorkMode(_In_ WorkMode_EM mode);

//获取行为记录
ULONG STDCALL GetMonitorMsg(_Out_ PMonitorMsg* pMsg, _Out_ PULONG msgNum);

//释放内存
void STDCALL FreeMonitorMsg(_In_ PMonitorMsg pMsg,_In_ ULONG msgNum);

//根据错误码获取错误信息
LPSTR STDCALL GetErrMsg(_In_ int err);

#ifdef __cplusplus
}
#endif

#endif
