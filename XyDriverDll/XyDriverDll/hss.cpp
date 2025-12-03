#include "hss.h"
#include "publicfun.h"
#include <WinSvc.h>
#include "AutoHandle.h"
#include <stdio.h>
#include <ctime>
#include <vector>
#include <map>
#include "cJSON.h"
#include <Shlwapi.h>
#include "rc4.h"

#define DriverName "XyDriver"
#define DriverLinkName "\\\\.\\XyDriverLink"
#define ConfigFile "driver.json"
#define Rc4Key "XyDriverRc4Key"

//打开共享内存
#define OPEN_SHAREMEM CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)
//发送开关数据
#define SENDCONFIG_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_WRITE_DATA)
//发送黑白名单配置
#define SENDWORKMODE_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_WRITE_DATA)
//发送策略数据
#define SENDPOLICY_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_WRITE_DATA)
//2270212
//#define SENDFSTOP_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x901,METHOD_BUFFERED,FILE_WRITE_DATA)

//驱动数据结构
typedef struct _NF_BUFFERS
{
	//存入数据
	unsigned __int64 inBuf;
	//存入数据长度
	unsigned __int64 inBufLen;
	unsigned __int64 outBuf;
	unsigned __int64 outBufLen;
} NF_BUFFERS, *PNF_BUFFERS;

typedef struct _NF_DATA
{
	//数据类型
	//int				code;
	//int				id;
	//数据长度
	unsigned long	bufferSize;
	//数据
	char 			buffer[1];
} NF_DATA, *PNF_DATA;

typedef  struct _NF_READ_RESULT
{
	unsigned __int64 length;
} NF_READ_RESULT, *PNF_READ_RESULT;


//安装驱动
//pDriverName 驱动名
//pDriverPath 驱动路径
ULONG InstallDriver(_In_ LPSTR pDriverPath, _In_ LPSTR pDriverName)
{
	ULONG ret = ERROR_DRIVER_INSTALL;

	SC_HANDLE manager_handle = NULL;
	SC_HANDLE server_handle = NULL;

	DWORD lastErr = 0;

	if (NULL == pDriverPath)
	{
		ret = ERROR_INVALID_VALUE;
		goto FINAL;
	}

	//打开资源管理器
	manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == manager_handle)
	{
		ret = ERROR_WIN_OPENSCMANAGER;
		goto FINAL;
	}

	//打开服务
	server_handle = OpenServiceA(manager_handle, pDriverName, SERVICE_ALL_ACCESS);
	if (NULL != server_handle)
	{
		lastErr = GetLastError();
		if(lastErr != 0)
			ret = ERROR_WIN_OPENSERVICE;
		ret = SUCCESS;
		goto FINAL;
	}

	//创建服务
	server_handle = CreateServiceA(manager_handle, pDriverName, pDriverName,
		SERVICE_ALL_ACCESS | STANDARD_RIGHTS_ALL,
		SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START,
		SERVICE_ERROR_NORMAL, pDriverPath, NULL, NULL, NULL, NULL, NULL);

	if (NULL == server_handle)
	{
		ret = ERROR_WIN_CREATESERVICE;
		goto FINAL;
	}

	//写入注册表
	if (!InstallRegistry(pDriverName))
	{
		goto FINAL;
	}

	ret = SUCCESS;

FINAL:
	if (NULL != server_handle)
	{
		//关闭服务句柄
		CloseServiceHandle(server_handle);
		server_handle = NULL;
	}

	if (NULL != manager_handle)
	{
		//关闭资源管理器句柄
		CloseServiceHandle(manager_handle);
		manager_handle = NULL;
	}

	return ret;
}

//启动驱动
//pDriverName 驱动名
ULONG StartDriver(_In_ LPSTR pDriverName)
{
	ULONG ret = ERROR_DRIVER_START;

	SC_HANDLE manager_handle = NULL;
	SC_HANDLE server_handle = NULL;

	//打开资源管理器
	manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == manager_handle)
	{
		ret = ERROR_WIN_OPENSCMANAGER;
		goto FINAL;
	}

	//打开服务
	server_handle = OpenServiceA(manager_handle, pDriverName, SERVICE_ALL_ACCESS);
	if (NULL == server_handle)
	{
		ret = ERROR_WIN_OPENSERVICE;
		goto FINAL;
	}

	SERVICE_STATUS status = { 0 };
	//查询驱动状态
	if(!QueryServiceStatus(server_handle, &status))
	{
		ret = ERROR_DRIVER_NOT_LOADED;
		goto FINAL;
	}

	//驱动正在运行
	if (status.dwCurrentState == SERVICE_RUNNING)
	{
		ret = SUCCESS;
		goto FINAL;
	}

	//启动驱动
	if (!StartService(server_handle, 0, NULL))
	{
		ret = ERROR_DRIVER_START;
		goto FINAL;
	}

	ret = SUCCESS;

FINAL:
	if (NULL != server_handle)
	{
		//关闭服务句柄
		CloseServiceHandle(server_handle);
		server_handle = NULL;
	}

	if (NULL != manager_handle)
	{
		//关闭资源管理器句柄
		CloseServiceHandle(manager_handle);
		manager_handle = NULL;
	}

	return ret;
}

//解析json文件
BOOL AnalysisJsonFile(_In_ LPSTR configFile, _Inout_ ULONG* configs, 
	_Out_ std::vector<std::string>* processList, _Out_ std::vector<std::string>* fileList)
{
	BOOL ret = FALSE;
	HANDLE hFileHandle = NULL;
	BYTE* fileData = NULL;
	PBYTE rsc_buf = NULL;

	cJSON* root = NULL;
	if (!PathFileExistsA(configFile))
	{
		goto FINAL;
	}

	hFileHandle = CreateFileA(configFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileHandle == INVALID_HANDLE_VALUE)
	{
		goto FINAL;
	}

	DWORD fileSize = 0;
	fileSize = GetFileSize(hFileHandle, NULL);
	if (fileSize == 0 || fileSize == INVALID_FILE_SIZE)
	{
		goto FINAL;
	}

	fileData = new BYTE[fileSize];
	memset(fileData, 0, fileSize);
	DWORD retSize = 0;
	if (!ReadFile(hFileHandle, fileData, fileSize, &retSize, NULL))
	{
		goto FINAL;
	}

	//解密
	//DWORD rscLen = fileSize / 2;
	//rsc_buf = new BYTE[rscLen];;
	//RtlZeroMemory(rsc_buf, rscLen);

	//BYTE rcKey[512] = { 0 };
	//int keyLen = strlen(Rc4Key);
	//asc_hex(fileData, rsc_buf, fileSize);
	//rc4_set_key(rcKey, (PBYTE)Rc4Key, keyLen);
	//rc4_transform(rcKey, rsc_buf, rscLen);

	rsc_buf = new BYTE[fileSize];
	RtlZeroMemory(rsc_buf, fileSize);
	RtlCopyMemory(rsc_buf, fileData, fileSize);

	if (rsc_buf[0] == '\0')
		goto FINAL;

	root = cJSON_Parse((char*)rsc_buf);
	if (root == NULL)
		goto FINAL;

	//黑白名单
	cJSON* monitor_mode = cJSON_GetObjectItem(root, "monitor_mode");
	if (monitor_mode)
	{
		if (strcmp(monitor_mode->valuestring,"black") != 0)
		{
			configs[Monitor_Mode] = 1;
		}
	}


	//文件开关
	cJSON* enable_file = cJSON_GetObjectItem(root, "enable_file_monitor");
	if (enable_file)
	{
		configs[Monitor_File] = enable_file->valueint;
	}

	//文件相关开关
	cJSON* file_monitor = cJSON_GetObjectItem(root, "file_monitor");
	if (file_monitor)
	{
		//文件创建
		cJSON* file_create = cJSON_GetObjectItem(file_monitor, "file_create");
		if(file_create)
			configs[MT_FileCreate] = file_create->valueint;

		//文件打开
		cJSON* file_open = cJSON_GetObjectItem(file_monitor, "file_open");
		if (file_open)
			configs[MT_FileOpen] = file_open->valueint;

		//文件读取
		cJSON* file_read = cJSON_GetObjectItem(file_monitor, "file_read");
		if (file_read)
			configs[MT_FileRead] = file_read->valueint;

		//文件关闭
		cJSON* file_close = cJSON_GetObjectItem(file_monitor, "file_close");
		if (file_close)
			configs[MT_FileClose] = file_close->valueint;

		//文件写入
		cJSON* file_write = cJSON_GetObjectItem(file_monitor, "file_write");
		if (file_write)
			configs[MT_FileWrite] = file_write->valueint;

		//文件删除
		cJSON* file_delete = cJSON_GetObjectItem(file_monitor, "file_delete");
		if (file_delete)
			configs[MT_FileDelete] = file_delete->valueint;
	}

	//进程开关
	cJSON* enable_process = cJSON_GetObjectItem(root, "enable_process_monitor");
	if (enable_process)
	{
		configs[Monitor_Process] = enable_process->valueint;
	}

	//进程相关开关
	cJSON* process_monitor = cJSON_GetObjectItem(root, "process_monitor");
	if (process_monitor)
	{
		//进程创建
		cJSON* process_create = cJSON_GetObjectItem(process_monitor, "process_create");
		if (process_create)
			configs[MT_ProcessCreate] = process_create->valueint;

		//进程打开
		cJSON* process_open = cJSON_GetObjectItem(process_monitor, "process_open");
		if (process_open)
			configs[MT_ProcessOpen] = process_open->valueint;

		//进程退出
		cJSON* process_exit = cJSON_GetObjectItem(process_monitor, "process_exit");
		if (process_exit)
			configs[MT_ProcessExit] = process_exit->valueint;

		//进程启动
		cJSON* process_start = cJSON_GetObjectItem(process_monitor, "process_start");
		if (process_start)
			configs[MT_ProcessStart] = process_start->valueint;
	}

	//线程开关
	cJSON* enable_pthread = cJSON_GetObjectItem(root, "enable_thread_monitor");
	if (enable_pthread)
	{
		configs[Monitor_Thread] = enable_pthread->valueint;
	}

	//线程相关开关
	cJSON* thread_monitor = cJSON_GetObjectItem(root, "thread_monitor");
	if (thread_monitor)
	{
		//线程创建
		cJSON* thread_create = cJSON_GetObjectItem(thread_monitor, "thread_create");
		if (thread_create)
			configs[MT_ThreadCreate] = thread_create->valueint;

		//线程打开
		cJSON* thread_open = cJSON_GetObjectItem(thread_monitor, "thread_open");
		if (thread_open)
			configs[MT_ThreadOpen] = thread_open->valueint;

		//线程退出
		cJSON* thread_exit = cJSON_GetObjectItem(thread_monitor, "thread_exit");
		if (thread_exit)
			configs[MT_ThreadExit] = thread_exit->valueint;

		//线程启动
		cJSON* thread_start = cJSON_GetObjectItem(thread_monitor, "thread_start");
		if (thread_start)
			configs[MT_ThreadStart] = thread_start->valueint;
	}


	//注册表开关
	cJSON* enable_reg = cJSON_GetObjectItem(root, "enable_reg_monitor");
	if (enable_reg)
	{
		configs[Monitor_Registry] = enable_reg->valueint;
	}

	//注册表相关开关
	cJSON* reg_monitor = cJSON_GetObjectItem(root, "reg_monitor");
	if (reg_monitor)
	{
		//注册表创建
		cJSON* reg_key_create = cJSON_GetObjectItem(reg_monitor, "reg_key_create");
		if (reg_key_create)
			configs[MT_RegCreateKey] = reg_key_create->valueint;

		//注册表打开
		cJSON* reg_key_open = cJSON_GetObjectItem(reg_monitor, "reg_key_open");
		if (reg_key_open)
			configs[MT_RegOpenKey] = reg_key_open->valueint;

		//注册表删除项
		cJSON* reg_key_delete = cJSON_GetObjectItem(reg_monitor, "reg_key_delete");
		if (reg_key_delete)
			configs[MT_RegDeleteKey] = reg_key_delete->valueint;

		//注册表重命名
		cJSON* reg_key_rename = cJSON_GetObjectItem(reg_monitor, "reg_key_rename");
		if (reg_key_rename)
			configs[MT_RenameKey] = reg_key_rename->valueint;

		//注册表枚举
		cJSON* reg_key_enum = cJSON_GetObjectItem(reg_monitor, "reg_key_enum");
		if (reg_key_enum)
			configs[MT_RegEnumKey] = reg_key_enum->valueint;

		//注册表设置值
		cJSON* reg_value_set = cJSON_GetObjectItem(reg_monitor, "reg_value_set");
		if (reg_value_set)
			configs[MT_RegSetValue] = reg_value_set->valueint;

		//注册表查询值
		cJSON* reg_value_query = cJSON_GetObjectItem(reg_monitor, "reg_value_query");
		if (reg_value_query)
			configs[MT_RegQueryValue] = reg_value_query->valueint;

		//注册表删除值
		cJSON* reg_value_delete = cJSON_GetObjectItem(reg_monitor, "reg_value_delete");
		if (reg_value_delete)
			configs[MT_RegDeleteValue] = reg_value_delete->valueint;
	}

	//网络开关
	cJSON* enable_socket = cJSON_GetObjectItem(root, "enable_socket_monitor");
	if (enable_socket)
	{
		configs[Monitor_Socket] = enable_socket->valueint;
	}

	//网络相关开关
	cJSON* socket_monitor = cJSON_GetObjectItem(root, "socket_monitor");
	if (socket_monitor)
	{
		//网络创建
		cJSON* socket_create = cJSON_GetObjectItem(socket_monitor, "socket_create");
		if (socket_create)
			configs[MT_SocketCreate] = socket_create->valueint;

		//网络绑定端口
		cJSON* socket_bind = cJSON_GetObjectItem(socket_monitor, "socket_bind");
		if (socket_bind)
			configs[MT_SocketBind] = socket_bind->valueint;

		//网路关闭
		cJSON* socket_close = cJSON_GetObjectItem(socket_monitor, "socket_close");
		if (socket_close)
			configs[MT_SocketClose] = socket_close->valueint;

		//网络连接
		cJSON* socket_connect = cJSON_GetObjectItem(socket_monitor, "socket_connect");
		if (socket_connect)
			configs[MT_SocketConnect] = socket_connect->valueint;

		//网络数据发送
		cJSON* socket_accept = cJSON_GetObjectItem(socket_monitor, "socket_accept");
		if (socket_accept)
			configs[MT_SocketSend] = socket_accept->valueint;

		//网络数据接收
		cJSON* socket_send = cJSON_GetObjectItem(socket_monitor, "socket_send");
		if (socket_send)
			configs[MT_SocketRecv] = socket_send->valueint;
	}

	//usb开关
	cJSON* enable_usb = cJSON_GetObjectItem(root, "enable_usb_monitor");
	if (enable_usb)
	{
		configs[Monitor_USB] = enable_usb->valueint;
	}

	//USB相关开关
	cJSON* usb_monitor = cJSON_GetObjectItem(root, "usb_monitor");
	if (usb_monitor)
	{
		//USB插入
		cJSON* usb_arrival = cJSON_GetObjectItem(usb_monitor, "usb_arrival");
		if (usb_arrival)
			configs[MT_USBArrival] = usb_arrival->valueint;

		//USB拔出
		cJSON* usb_removal = cJSON_GetObjectItem(usb_monitor, "usb_removal");
		if (usb_removal)
			configs[MT_USBRemoval] = usb_removal->valueint;
	}

	cJSON* process_list = cJSON_GetObjectItem(root, "process_list");
	if (process_list)
	{
		DWORD processArraySize = cJSON_GetArraySize(process_list);
		for (DWORD i = 0; i < processArraySize; i++)
		{
			cJSON *item_array = cJSON_GetArrayItem(process_list, i);
			if (item_array->type != cJSON_String)
				continue;


			if (item_array->valuestring != NULL && item_array->valuestring[0] != '\0')
			{
				processList->push_back(item_array->valuestring);
			}
		}
	}


	cJSON* file_list = cJSON_GetObjectItem(root, "file_list");
	if (file_list)
	{
		DWORD fileArraySize = cJSON_GetArraySize(file_list);
		for (DWORD i = 0; i < fileArraySize; i++)
		{
			cJSON *item_array = cJSON_GetArrayItem(file_list, i);
			if (item_array->type != cJSON_String)
				continue;

			if (item_array->valuestring != NULL && item_array->valuestring[0] != '\0')
			{
				fileList->push_back(item_array->valuestring);
			}
		}
	}


	ret = TRUE;
FINAL:
	if (root)
	{
		cJSON_Delete(root);
		root = NULL;
	}

	if (fileData)
	{
		delete[] fileData;
		fileData = NULL;
	}

	if (rsc_buf)
	{
		delete[] rsc_buf;
		rsc_buf = NULL;
	}

	if (hFileHandle)
	{
		CloseHandle(hFileHandle);
		hFileHandle = NULL;
	}

	return ret;
}

//加载驱动
ULONG STDCALL LoadDriver(_In_ LPSTR pDriverPath)
{
	ULONG ret = SUCCESS;

	ret = InstallDriver(pDriverPath, DriverName);
	if (SUCCESS != ret)
		return ret;

	ret = StartDriver(DriverName);
	if (SUCCESS != ret)
		return ret;

	std::string strDriverPath(pDriverPath);
	size_t last = strDriverPath.find_last_of("\\");
	strDriverPath = strDriverPath.substr(0, last+1);
	strDriverPath += ConfigFile;

	Config configs = { Monitor_Mode };
	std::vector<std::string> processList;
	std::vector<std::string> fileList;
	if (!AnalysisJsonFile((LPSTR)strDriverPath.c_str(), configs, &processList, &fileList))
	{
		//ret = ERROR_ANALYSISJSON;
		//return ret;
	}		

	ret = SetWorkMode(configs[Monitor_Mode] == 0? BLACK: WHITE);
	if (ret != SUCCESS)
	{
		return ret;
	}
	configs[Monitor_Mode] = 0;
	ret = SetConfig(&configs);
	if (ret != SUCCESS)
	{
		return ret;
	}

	for (DWORD i = 0; i < processList.size();i++)
	{
		Policy policy;
		policy.type = POLICY_EXE_LIST;
		policy.operation = ADD;
		RtlZeroMemory(policy.data,512);
		RtlCopyMemory(policy.data, processList[i].c_str(),512);

		ret = SetPolicy(&policy);
		if (ret != SUCCESS)
		{
			return ret;
		}
	}

	for (DWORD i = 0; i < fileList.size(); i++)
	{
		Policy policy;
		policy.type = POLICY_FILE_LIST;
		policy.operation = ADD;
		RtlZeroMemory(policy.data, 512);
		RtlCopyMemory(policy.data, fileList[i].c_str(), 512);

		ret = SetPolicy(&policy);
		if (ret != SUCCESS)
		{
			return ret;
		}
	}

	return ret;
}

//停止驱动
//pDriverName 驱动名
ULONG StopDriver(_In_ LPSTR pDriverName)
{
	ULONG ret = ERROR_DRIVER_STOP;

	SC_HANDLE manager_handle = NULL;
	SC_HANDLE server_handle = NULL;

	//打开资源管理器
	manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (NULL == manager_handle)
	{
		ret = ERROR_WIN_OPENSCMANAGER;
		goto FINAL;
	}

	//打开服务
	server_handle = OpenServiceA(manager_handle, pDriverName, SERVICE_ALL_ACCESS);
	if (NULL == server_handle)
	{
		ret = ERROR_WIN_OPENSERVICE;
		goto FINAL;
	}

	SERVICE_STATUS status = { 0 };
	//查询服务状态
	BOOL result = QueryServiceStatus(server_handle, &status);
	if (!result)
	{
		ret = ERROR_DRIVER_NOT_LOADED;
		goto FINAL;
	}
	DWORD bytesNeeded = 0;
	//服务退出
	if (result && status.dwCurrentState != SERVICE_STOPPED)
	{
		if (!ControlService(server_handle, SERVICE_CONTROL_STOP, &status))
		{
			goto FINAL;
		}
		Sleep(status.dwWaitHint);

		// 判断超时
		INT timeOut = 0;
		while (status.dwCurrentState != SERVICE_STOPPED) 
		{
			timeOut++;
			QueryServiceStatus(server_handle, &status);
			Sleep(50);
			if (timeOut > 10)
				break;
		}
		if (timeOut > 10) {
			goto FINAL;
		}
	}

	ret = SUCCESS;
FINAL:
	if (NULL != server_handle)
	{
		//关闭服务句柄
		CloseServiceHandle(server_handle);
		server_handle = NULL;
	}

	if (NULL != manager_handle)
	{
		//关闭资源管理器句柄
		CloseServiceHandle(manager_handle);
		manager_handle = NULL;
	}

	return ret;
}

//卸载驱动
//pDriverName 驱动名
ULONG UninstallDriver(_In_ LPSTR pDriverName)
{
	ULONG ret = ERROR_DRIVER_UNINSTALL;

	SC_HANDLE manager_handle = NULL;
	SC_HANDLE server_handle = NULL;

	//打开资源管理器
	manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (manager_handle == NULL)
	{
		ret = ERROR_WIN_OPENSCMANAGER;
		goto FINAL;
	}

	//打开服务
	server_handle = OpenServiceA(manager_handle, pDriverName, SERVICE_ALL_ACCESS);
	if (server_handle == NULL)
	{
		ret = ERROR_WIN_OPENSERVICE;
		goto FINAL;
	}

	SERVICE_STATUS status = { 0 };
	//查询服务状态
	BOOL result = QueryServiceStatus(server_handle, &status);
	if (!result)
	{
		ret = ERROR_DRIVER_NOT_LOADED;
		goto FINAL;
	}
	//服务正在运行
	if (status.dwCurrentState == SERVICE_RUNNING)
	{
		ret = ERROR_DRIVER_STOP;
		goto FINAL;
	}

	//删除服务
	if (!DeleteService(server_handle))
	{
		ret = ERROR_WIN_DELETESERVICE;
		goto FINAL;
	}

	ret = SUCCESS;

FINAL:
	if (NULL != server_handle)
	{
		//关闭服务句柄
		CloseServiceHandle(server_handle);
		server_handle = NULL;
	}

	if (NULL != manager_handle)
	{
		//关闭资源管理器句柄
		CloseServiceHandle(manager_handle);
		manager_handle = NULL;
	}

	return ret;
}


//卸载驱动
ULONG STDCALL UnloadDriver()
{
	ULONG ret = SUCCESS;

	ret = StopDriver(DriverName);
	if (SUCCESS != ret)
	{
		return ret;
	}

	ret = UninstallDriver(DriverName);

	return ret;
}


//打开设备
//pDriverLinkName 驱动设备名
HANDLE OpenDriverLink(_In_ LPSTR pDriverLinkName)
{
	HANDLE hDriverHandle = NULL;
	//打开设备
	hDriverHandle = CreateFileA(pDriverLinkName, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (hDriverHandle == INVALID_HANDLE_VALUE)
	{
		hDriverHandle = NULL;
	}

	return hDriverHandle;
}

//关闭设备
//hDriverLinkHandle 设备句柄（由【OpenDriverLink】接口返回）
BOOL CloseDriverLink(_In_ HANDLE hDriverLinkHandle)
{
	BOOL ret = FALSE;
	if (hDriverLinkHandle)
	{
		ret = CloseHandle(hDriverLinkHandle);
		hDriverLinkHandle = NULL;
	}

	return ret;
}


//设置开关配置
ULONG STDCALL SetConfig(_In_ Config *pConfig)
{
	if (NULL == pConfig)
	{
		return ERROR_INVALID_VALUE;
	}

	HANDLE hDriverHandle = OpenDriverLink(DriverLinkName);
	if (NULL == hDriverHandle)
		return ERROR_DRIVER_OPEN;

	OVERLAPPED ol;
	AutoEventHandle hEvent;
	
	ol.hEvent = hEvent;
	
	*pConfig[Monitor_Mode] = BLACK;
	//向驱动发送创建共享内存消息
	if (!DeviceIoControl(hDriverHandle, SENDCONFIG_CTL, pConfig, Monitor_Max*sizeof(ULONG), NULL,0,NULL, &ol))
	{
		return ERROR_DRIVER_SEND;
	}

	CloseDriverLink(hDriverHandle);
	hDriverHandle = NULL;

	return SUCCESS;
}
//配置策略
ULONG STDCALL SetPolicy(_In_ PPolicy pPolicy)
{
	if (NULL == pPolicy)
	{
		return ERROR_INVALID_VALUE;
	}

	HANDLE hDriverHandle = OpenDriverLink(DriverLinkName);
	if (NULL == hDriverHandle)
		return ERROR_DRIVER_OPEN;

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	ol.hEvent = hEvent;

	//向驱动发送创建共享内存消息
	if (!DeviceIoControl(hDriverHandle, SENDPOLICY_CTL, pPolicy, sizeof(Policy), NULL, 0, NULL, &ol))
	{
		return ERROR_DRIVER_SEND;
	}

	CloseDriverLink(hDriverHandle);
	hDriverHandle = NULL;

	return SUCCESS;
}

//设置工作模式
ULONG STDCALL SetWorkMode(_In_ WorkMode_EM mode)
{
	HANDLE hDriverHandle = OpenDriverLink(DriverLinkName);
	if (NULL == hDriverHandle)
		return ERROR_DRIVER_OPEN;

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	ol.hEvent = hEvent;

	ULONG workMode = mode;
	//向驱动发送黑白名单配置
	if (!DeviceIoControl(hDriverHandle, SENDWORKMODE_CTL, &workMode, sizeof(ULONG), NULL, 0, NULL, &ol))
	{
		return ERROR_DRIVER_SEND;
	}

	CloseDriverLink(hDriverHandle);
	hDriverHandle = NULL;

	return SUCCESS;
}

//打开驱动的共享内存
//hDriver 驱动句柄
//pNfBuffers 缓冲区
ULONG OpenShareMem(_In_ HANDLE hDriverLinkHandle, _Out_ PNF_BUFFERS pNfBuffers)
{
	if (NULL == pNfBuffers || NULL == hDriverLinkHandle)
	{
		return ERROR_INVALID_VALUE;
	}

	memset(pNfBuffers, 0, sizeof(NF_BUFFERS));

	OVERLAPPED ol;
	AutoEventHandle hEvent;

	ol.hEvent = hEvent;
	//向驱动发送创建共享内存消息
	if (!DeviceIoControl(hDriverLinkHandle, OPEN_SHAREMEM, NULL, 0, pNfBuffers, sizeof(NF_BUFFERS), NULL, &ol))
	{
		return ERROR_DRIVER_SEND;
	}

	return SUCCESS;
}

//简单处理数据空字段
BOOL DealOutData(PMonitorMsg pMonitorMsg)
{
	if (pMonitorMsg == NULL)
		return FALSE;

	//转换路径
	char commonExe[512] = { 0 };
	RtlCopyMemory(commonExe, pMonitorMsg->common.exe,sizeof(pMonitorMsg->common.exe));
	GetNTLinkName((LPWCH)commonExe, pMonitorMsg->common.exe, sizeof(pMonitorMsg->common.exe));

	switch (pMonitorMsg->common.type)
	{
	case Monitor_Process:
	{
		PPROCESSINFO pProcessInfo = (PPROCESSINFO)pMonitorMsg->data;

		//设备链接名转换盘符
		WCHARMAX parenPath = { 0 };
		RtlCopyMemory(parenPath, pProcessInfo->parenPath, sizeof(pProcessInfo->parenPath));
		GetNTLinkName(parenPath, (LPSTR)pProcessInfo->parenPath, sizeof(pProcessInfo->parenPath));
	
		if (pProcessInfo->processType == MT_ProcessStart || pProcessInfo->processType == MT_ProcessOpen)
		{
			//根据进程id获取进程路径
			if (pMonitorMsg->common.exe[0] == 0)
				GetProcessPathByPid(pMonitorMsg->common.pid, pMonitorMsg->common.exe, sizeof(pMonitorMsg->common.exe));
			//根据进程id获取父进程id
			if (pMonitorMsg->common.ppid == 0)
				pMonitorMsg->common.ppid = GetPPidByPid(pMonitorMsg->common.pid);
		}

		//根据进程id获取进程创建时间
		if (pProcessInfo->createTime == 0)
		{
			pProcessInfo->createTime = GetProcessCreateTimeByPid(pMonitorMsg->common.pid);
		}

		break;
	}
	case Monitor_Thread:
	{
		PTHREADINFO pThreadInfo = (PTHREADINFO)pMonitorMsg->data;	
		if (pThreadInfo->threadType == MT_ThreadStart || pThreadInfo->threadType == MT_ThreadOpen)
		{
			//根据进程id获取进程路径
			if (pMonitorMsg->common.exe[0] == 0)
				GetProcessPathByPid(pMonitorMsg->common.pid, pMonitorMsg->common.exe, sizeof(pMonitorMsg->common.exe));
			//根据进程id获取父进程id
			if(pMonitorMsg->common.ppid == 0)
				pMonitorMsg->common.ppid = GetPPidByPid(pMonitorMsg->common.pid);
		}

		//根据进程id获取进程创建时间
		if (pThreadInfo->createTime == 0)
		{
			pThreadInfo->createTime = GetProcessCreateTimeByPid(pMonitorMsg->common.pid);
		}

		break;
	}
	case Monitor_Registry:
	{
		PREGISTERINFO pRegisteryInfo = (PREGISTERINFO)pMonitorMsg->data;

		//根据进程id获取进程创建时间
		if (pRegisteryInfo->createTime == 0)
		{
			pRegisteryInfo->createTime = GetProcessCreateTimeByPid(pMonitorMsg->common.pid);
		}
		break;
	}
	case Monitor_File:
	{
		PFILEINFO pFileInfo = (PFILEINFO)pMonitorMsg->data;

		//设备链接名转换盘符
		{
			WCHARMAX fileName = { 0 };
			RtlCopyMemory(fileName, pFileInfo->fileName, sizeof(pFileInfo->fileName));
			GetNTLinkName(fileName, (LPSTR)pFileInfo->fileName, sizeof(pFileInfo->fileName));

			WCHARMAX filePath = { 0 };
			RtlCopyMemory(filePath, pFileInfo->filePath, sizeof(pFileInfo->filePath));
			GetNTLinkName(filePath, (LPSTR)pFileInfo->filePath, sizeof(pFileInfo->filePath));
		}

		//根据进程id获取进程创建时间
		if (pFileInfo->createTime == 0)
		{
			pFileInfo->createTime = GetProcessCreateTimeByPid(pMonitorMsg->common.pid);
		}

		if (pFileInfo->fileCreateTime == 0)
		{
			pFileInfo->fileCreateTime = GetFileCreateTimeByFileName(pFileInfo->fileName);
		}

		break;
	}
	case Monitor_USB:
	{
		PHOTPLUGINFO pHotInfo = (PHOTPLUGINFO)pMonitorMsg->data;
		//根据进程id获取进程路径
		//if (pMonitorMsg->common.exe[0] == 0)
		//	GetProcessPathByPid(pMonitorMsg->common.pid, pMonitorMsg->common.exe, sizeof(pMonitorMsg->common.exe));
		
		//根据进程id获取进程创建时间
		if (pHotInfo->createTime == 0)
		{
			pHotInfo->createTime = GetProcessCreateTimeByPid(pMonitorMsg->common.pid);
		}

		break;
	}
	case Monitor_Socket:
	{
		PNETWORKINFO pNetInfo = (PNETWORKINFO)pMonitorMsg->data;
		if (pNetInfo->type == MT_SocketConnect || pNetInfo->type == MT_SocketSend || pNetInfo->type == MT_SocketRecv)
		{
			//根据进程id获取进程名
			if (pMonitorMsg->common.comm[0] == '\0')
				GetProcessNameByPid(pMonitorMsg->common.pid, pMonitorMsg->common.comm, sizeof(pMonitorMsg->common.comm));
		}

		if (pNetInfo->type == MT_SocketClose)
		{
			//根据进程id获取进程路径
			if (pMonitorMsg->common.exe[0] == 0)
				GetProcessPathByPid(pMonitorMsg->common.pid, pMonitorMsg->common.exe, sizeof(pMonitorMsg->common.exe));

			//根据进程id获取进程名
			if (pMonitorMsg->common.comm[0] == '\0')
				GetProcessNameByPid(pMonitorMsg->common.pid, pMonitorMsg->common.comm, sizeof(pMonitorMsg->common.comm));
		}

		//根据进程id获取进程创建时间
		if (pNetInfo->createTime == 0)
		{
			pNetInfo->createTime = GetProcessCreateTimeByPid(pMonitorMsg->common.pid);
		}

		break;
	}
	}


	return TRUE;
}

//去重
BOOL DedupliCationData(std::vector<PNF_DATA>* pNfDatas,std::map<std::string, PNF_DATA>* pOutMap)
{
	BOOL ret = FALSE;
	if (pNfDatas == NULL || pNfDatas->empty())
		return ret;
	
	for (DWORD i = 0; i < pNfDatas->size(); i++)
	{
		PNF_DATA pNfData = (*pNfDatas)[i];
		if (pNfData == NULL || pNfData->bufferSize <= sizeof(MonitorMsgCommon))
			continue;
		
		PBYTE p = (PBYTE)pNfData->buffer;
		PMonitorMsgCommon pmsg = (PMonitorMsgCommon)p;
		if (pmsg == NULL)
			continue;
	 
		//进程id,进程名,采集时间
		std::string hashStr = FormatString("%d,%s,%d", pmsg->pid, pmsg->comm, pmsg->timestamp);

		switch (pmsg->type)
		{
		case Monitor_Process:
		{
			PPROCESSINFO pProcessInfo = (PPROCESSINFO)(p + sizeof(MonitorMsgCommon));
			hashStr += FormatString(",%d", pProcessInfo->processType);
			break;
		}
		case Monitor_Thread:
		{
			PTHREADINFO pThreadInfo = (PTHREADINFO)(p + sizeof(MonitorMsgCommon));
			hashStr += FormatString(",%d,%d", pThreadInfo->threadType, pThreadInfo->threadId);
			break;
		}
		case Monitor_File:
		{
			PFILEINFO pFileInfo = (PFILEINFO)(p + sizeof(MonitorMsgCommon));
			std::wstring wFileName(pFileInfo->fileName);
			std::string locale = "";
			std::string strFileName = wstring2string(wFileName, locale);
			hashStr += FormatString(",%d,%s", pFileInfo->type, strFileName.c_str());
			break;
		}
		case Monitor_Registry:
		{
			PREGISTERINFO pRegisterInfo = (PREGISTERINFO)(p + sizeof(MonitorMsgCommon));

			std::wstring wObject(pRegisterInfo->object);
			std::wstring wName(pRegisterInfo->name);
			std::string locale = "";
			std::string strObject = wstring2string(wObject, locale);
			std::string strName = wstring2string(wName, locale);

			hashStr += FormatString(",%d,%s,%s", pRegisterInfo->type, strObject.c_str(), strName.c_str());
			break;
		}
		case Monitor_Socket:
		{
			PNETWORKINFO pNetWorkInfo = (PNETWORKINFO)(p + sizeof(MonitorMsgCommon));
			std::wstring wprotocolName(pNetWorkInfo->protocolName);
			std::string locale = "";
			std::string strprotocolName = wstring2string(wprotocolName, locale);

			hashStr += FormatString(",%d,%d:%d,%d:%d,%s", pNetWorkInfo->type,
				pNetWorkInfo->localIp, pNetWorkInfo->localPort, pNetWorkInfo->remoteIP, pNetWorkInfo->remotePort,
				strprotocolName.c_str());
			break;
		}
		case Monitor_USB:
		{
			PHOTPLUGINFO pUSBInfo = (PHOTPLUGINFO)(p + sizeof(MonitorMsgCommon));
			std::wstring wLinkName(pUSBInfo->symbolicLinkName);
			std::string locale = "";
			std::string strLinkName = wstring2string(wLinkName, locale);
			hashStr += FormatString(",%d,%s", pUSBInfo->type, strLinkName.c_str());
			break;
		}
		case Monitor_Image:
		{
			PLOADIMAGEINFO pImageInfo = (PLOADIMAGEINFO)(p + sizeof(MonitorMsgCommon));
			std::wstring wImagePath(pImageInfo->imagePath);
			std::string locale = "";
			std::string strImagePath = wstring2string(wImagePath, locale);
			hashStr += FormatString(",%s", strImagePath.c_str());
			break;
		}
		}

		std::map<std::string, PNF_DATA>::iterator itr = pOutMap->find(hashStr);
		if (itr == pOutMap->end())
		{
			pOutMap->insert(std::make_pair(hashStr, pNfData));
		}
	}

	ret = TRUE;
	return ret;
}

//获取行为记录
ULONG STDCALL GetMonitorMsg(_Out_ PMonitorMsg* pMsg,_Out_ PULONG msgNum)
{
	ULONG ret = ERROR_DRIVER_READ;

	HANDLE hDriverLinkHandle = NULL;
	NF_BUFFERS nfBuffers = { 0 };

	OVERLAPPED ol;
	NF_READ_RESULT rr;
	DWORD readBytes;
	AutoEventHandle ioEvent;
	AutoEventHandle stopEvent;
	HANDLE events[] = { ioEvent, stopEvent };

	std::vector<PNF_DATA> nfDatas;	
	std::map<std::string, PNF_DATA> mapData;
	std::map<std::string, PNF_DATA>::iterator itr;

	hDriverLinkHandle = OpenDriverLink(DriverLinkName);
	if (NULL == hDriverLinkHandle)
	{
		ret = ERROR_DRIVER_OPEN;
		goto FINAL;
	}
			
	ret = OpenShareMem(hDriverLinkHandle, &nfBuffers);
	if(SUCCESS != ret)
	{
		goto FINAL;
	}
	
	memset(&ol, 0, sizeof(ol));

	ol.hEvent = ioEvent;
	//读取驱动消息
	if (!ReadFile(hDriverLinkHandle, &rr, sizeof(rr), NULL, &ol))
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			OutputDebugString(L"ReadFile Error!");
			goto FINAL;
		}
	}
	
	DWORD dwRes;
	DWORD waitTimeout = 10;
	while(TRUE)
	{
		//等待获取消息
		dwRes = WaitForMultipleObjects(
			sizeof(events) / sizeof(events[0]),
			events,
			FALSE,
			waitTimeout);
	
		//超时
		if (dwRes == WAIT_TIMEOUT)
		{
			waitTimeout = 5 * 1000;
			continue;
		}
		else if (dwRes != WAIT_OBJECT_0)
		{
			goto FINAL;
		}
		//等待结束
		dwRes = WaitForSingleObject(stopEvent, 0);
		if (dwRes == WAIT_OBJECT_0)
		{
			goto FINAL;
		}
	
		//获取数据
		if (!GetOverlappedResult(hDriverLinkHandle, &ol, &readBytes, FALSE))
		{
			goto FINAL;
		}
	
		break;
	}
	
	readBytes = (DWORD)rr.length;
	if (readBytes > nfBuffers.inBufLen)
		readBytes = (DWORD)nfBuffers.inBufLen;
	
	//数据
	PNF_DATA pData = (PNF_DATA)nfBuffers.inBuf;
	DWORD offset = 0;
	
	ULONG bufferSize = 0;
	while (readBytes > 0)
	{
		if (pData->buffer)
		{	
			//if(NULL != callback)
			//{
			//	//调用回调函数
			//	callback(pData->code, pData->buffer, pData->bufferSize);
			//}

			bufferSize += pData->bufferSize;
			nfDatas.push_back(pData);
		}
	
		offset += sizeof(NF_DATA) - 1 + pData->bufferSize;
		if (offset + sizeof(NF_DATA) - 1 >= readBytes)
		{
			break;
		}
	
		pData = (PNF_DATA)(nfBuffers.inBuf + offset);
	}
	
	//对数据进行去重
	if(!DedupliCationData(&nfDatas, &mapData))
		goto FINAL;

	*msgNum = mapData.size();

	PMonitorMsg pMonitorMsg = new MonitorMsg[mapData.size()];
	if (!pMonitorMsg)
		goto FINAL;

	RtlZeroMemory(pMonitorMsg, sizeof(MonitorMsg) * mapData.size());

	PMonitorMsg p = pMonitorMsg;
	itr = mapData.begin();
	for (; itr != mapData.end(); itr++, p++)
	{
		PNF_DATA pNfData = itr->second;
		RtlCopyMemory(p, pNfData->buffer, sizeof(MonitorMsgCommon));
		
		LONG buffSize = pNfData->bufferSize - sizeof(MonitorMsgCommon);
		if (buffSize < 0)
		{
			continue;
		}
		p->data = new char[buffSize];
		RtlCopyMemory(p->data, pNfData->buffer+ sizeof(MonitorMsgCommon), buffSize);

		//简单解析数据
		DealOutData(p);
	}

	*pMsg = pMonitorMsg;


	//PBYTE pBufferData = new BYTE[bufferSize];
	//if (NULL == pBufferData)
	//{
	//	goto FINAL;
	//}
	//RtlZeroMemory(pBufferData, bufferSize);

	//BYTE* pOffset = pBufferData;
	//for (ULONG i = 0; i < nfDatas.size(); i++)
	//{
	//	RtlCopyMemory(pOffset, nfDatas[i]->buffer, nfDatas[i]->bufferSize);
	//	pOffset += nfDatas[i]->bufferSize;
	//}

	//*pMsg = (PMonitorMsg)pBufferData;


	nfBuffers = { 0 };
	nfDatas.clear();
	nfDatas.swap(std::vector<PNF_DATA>());

	mapData.clear();
	mapData.swap(std::map<std::string, PNF_DATA>());

	ret = SUCCESS;

FINAL:
	if (hDriverLinkHandle)
	{
		CloseDriverLink(hDriverLinkHandle);
		hDriverLinkHandle = NULL;
	}

	return ret;
}

//释放内存
VOID STDCALL FreeMonitorMsg(_In_ PMonitorMsg pMsg, _In_ ULONG msgNum)
{
	if (pMsg)
	{
		PMonitorMsg p = pMsg;
		for (ULONG i = 0; i < msgNum; i++, p++)
		{
			if (p->data)
			{
				delete[] p->data;
				p->data = NULL;
			}
		}
		delete[] pMsg;
		pMsg = NULL;
	}
}

LPSTR STDCALL GetErrMsg(_In_ int err)
{
	switch (err)
	{
	case ERROR_DRIVER_FILE_NOT_EXIST:
		return "驱动文件不存在";
	case ERROR_DRIVER_NOT_LOADED:
		return "驱动未加载";
	case ERROR_DRIVER_INSTALL:
		return "驱动安装失败";
	case ERROR_DRIVER_UNINSTALL:
		return "驱动卸载失败";
	case ERROR_DRIVER_START:
		return "驱动启动失败";
	case ERROR_DRIVER_STOP:
		return "驱动停止失败";
	case ERROR_DRIVER_OPEN:
		return "打开驱动设备或驱动文件失败";
	case ERROR_DRIVER_SEND:
		return "发送通信指令失败";
	case ERROR_DRIVER_READ:
		return "获取数据失败";
	case ERROR_INVALID_VALUE:
		return "无效的参数";
	case ERROR_MEMORY:
		return "内存错误";
	case ERROR_WIN_OPENSCMANAGER:
		return "打开资源管理器失败";
	case ERROR_WIN_OPENSERVICE:
		return "打开服务失败";
	case ERROR_WIN_CREATESERVICE:
		return "创建服务失败";
	case ERROR_WIN_WRITEREGISTRY:
		return "写入注册表失败";
	case ERROR_WIN_DELETESERVICE:
		return "删除服务失败";
	default:
		return "未知的错误";
	}

	return "";
}
