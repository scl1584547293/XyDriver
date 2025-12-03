
// dllMFCDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "dllMFC.h"
#include "dllMFCDlg.h"
#include "afxdialogex.h"
#include "..\XyDriverDll\hss.h"
#include "rc4.h"
#include <time.h>


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//#define WINXP


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CdllMFCDlg 对话框


CdllMFCDlg::CdllMFCDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DLLMFC_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}


void CdllMFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_myEdit);
	DDX_Control(pDX, IDC_EDIT2, m_driverEdit);
	DDX_Control(pDX, IDC_EDIT3, m_ConfigEdit);
}

BEGIN_MESSAGE_MAP(CdllMFCDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CdllMFCDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON4, &CdllMFCDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON7, &CdllMFCDlg::OnBnClickedButton7)
	ON_BN_CLICKED(IDC_BUTTON10, &CdllMFCDlg::OnBnClickedButton10)
	ON_BN_CLICKED(IDC_BUTTON13, &CdllMFCDlg::OnBnClickedButton13)
	ON_BN_CLICKED(IDC_CHECK2, &CdllMFCDlg::OnBnClickedCheck2)
	ON_BN_CLICKED(IDC_CHECK3, &CdllMFCDlg::OnBnClickedCheck3)
	ON_BN_CLICKED(IDC_CHECK4, &CdllMFCDlg::OnBnClickedCheck4)
	ON_BN_CLICKED(IDC_CHECK6, &CdllMFCDlg::OnBnClickedCheck6)
	ON_BN_CLICKED(IDC_CHECK5, &CdllMFCDlg::OnBnClickedCheck5)
	ON_BN_CLICKED(IDC_CHECK7, &CdllMFCDlg::OnBnClickedCheck7)
	ON_BN_CLICKED(IDC_CHECK41, &CdllMFCDlg::OnBnClickedCheck41)
	ON_BN_CLICKED(IDC_CHECK42, &CdllMFCDlg::OnBnClickedCheck42)
	ON_BN_CLICKED(IDC_CHECK38, &CdllMFCDlg::OnBnClickedCheck38)
	ON_BN_CLICKED(IDC_CHECK39, &CdllMFCDlg::OnBnClickedCheck39)
	ON_BN_CLICKED(IDC_CHECK40, &CdllMFCDlg::OnBnClickedCheck40)
	ON_BN_CLICKED(IDC_BUTTON8, &CdllMFCDlg::OnBnClickedButton8)
	ON_BN_CLICKED(IDC_CHECK1, &CdllMFCDlg::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_BUTTON2, &CdllMFCDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_CHECK47, &CdllMFCDlg::OnBnClickedCheck47)
	ON_BN_CLICKED(IDC_CHECK8, &CdllMFCDlg::OnBnClickedCheck8)
	ON_BN_CLICKED(IDC_CHECK45, &CdllMFCDlg::OnBnClickedCheck45)
	ON_BN_CLICKED(IDC_BUTTON3, &CdllMFCDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_CHECK46, &CdllMFCDlg::OnBnClickedCheck46)
	ON_BN_CLICKED(IDC_BUTTON9, &CdllMFCDlg::OnBnClickedButton9)
	ON_BN_CLICKED(IDC_BUTTON11, &CdllMFCDlg::OnBnClickedButton11)
END_MESSAGE_MAP()

// CdllMFCDlg 消息处理程序

BOOL CdllMFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

#ifndef WINXP
	//winxp需要屏蔽此代码(管理员无法实现拖拽问题)
	ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
	ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);
#endif

	//ShowWindow(SW_MINIMIZE);

	InitComboBox();
	InitCheckBox();



	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CdllMFCDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CdllMFCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CdllMFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

typedef ULONG(STDCALL *_LoadDriver)(_In_ LPSTR pDriverPath);
typedef ULONG(STDCALL *_UnloadDriver)();
typedef ULONG(STDCALL *_SetPolicy)(_In_ PPolicy pPolicy);
typedef ULONG (STDCALL *_SetConfig)(_In_ Config *pConfig);
typedef ULONG(STDCALL *_SetWorkMode)(_In_ WorkMode_EM mode);
typedef ULONG(STDCALL *_GetMonitorMsg)(_Out_ PMonitorMsg* pMsg, _Out_ PULONG msgNum);
typedef VOID (STDCALL* _FreeMonitorMsg)(_In_ PMonitorMsg pMsg, _In_ ULONG msgNum);

//#include <setupapi.h> 
//#include<winioctl.h>

static BOOL g_isAutoCollect = FALSE;
static HANDLE g_hThread = NULL;

//安装驱动
void CdllMFCDlg::OnBnClickedButton1()
{
	WCHAR dllName[255] = { 0 };
	GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(L"动态库为空");
		return;
	}
	
	WCHAR driverPath[255] = { 0 };
	GetDlgItemText(IDC_EDIT2, driverPath, 254);
	if (driverPath[0] == L'\0')
	{
		MessageBox(L"驱动路径为空");
		return;
	}

	HMODULE hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(L"动态库加载失败");
		return;
	}

	_LoadDriver installDriver = (_LoadDriver)GetProcAddress(hModule, "LoadDriver");

	//_InstallDriver installDriver = (_InstallDriver)GetProcAddress(hModule, "InstallDriver");

	if (NULL == installDriver)
	{
		FreeLibrary(hModule);
		hModule = NULL;
		MessageBox(L"动态库获取函数失败失败");
		return;
	}

	std::wstring wDriverPath = driverPath;
	std::string locale = "";
	std::string strDriverPath = wstring2string(wDriverPath, locale);

	ULONG ret = installDriver((char*)strDriverPath.c_str());
	if (ret != 0)
	{
		FreeLibrary(hModule);
		hModule = NULL;

		DWORD error = GetLastError();

		WCHAR tmp[24] = { 0 };
		wsprintf(tmp,L"安装驱动失败:%s(%d)", GetErrorString(ret), error);

		MessageBox(tmp);
		return;
	}

	FreeLibrary(hModule);
	hModule = NULL;
	MessageBox(L"安装驱动成功");
}

//卸载驱动
void CdllMFCDlg::OnBnClickedButton4()
{
	WCHAR dllName[255] = { 0 };
	GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(L"动态库为空");
		return;
	}

	HMODULE hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(L"动态库加载失败");
		return;
	}

	g_isAutoCollect = FALSE;

	if (g_hThread)
	{
		TerminateThread(g_hThread, 0);
		CloseHandle(g_hThread);
		g_hThread = NULL;
	}

	_UnloadDriver uninstallDriver = (_UnloadDriver)GetProcAddress(hModule, "UnloadDriver");


	//_UninstallDriver uninstallDriver = (_UninstallDriver)GetProcAddress(hModule, "UninstallDriver");
	if (NULL == uninstallDriver)
	{
		FreeLibrary(hModule);
		hModule = NULL;
		MessageBox(L"动态库获取函数失败失败");
		return;
	}

	ULONG ret = uninstallDriver();

	if (ret != 0)
	{
		FreeLibrary(hModule);
		hModule = NULL;

		DWORD error = GetLastError();

		WCHAR tmp[24] = { 0 };
		wsprintf(tmp, L"卸载驱动失败:%s(%d)", GetErrorString(ret),error);

		MessageBox(tmp);
		return;
	}

	FreeLibrary(hModule);
	hModule = NULL;
	MessageBox(L"卸载驱动成功");
#ifdef WINXP
	MessageBox(L"请重启电脑！！！");
#endif
}

#define LOGFILEMAXSIZE 100*1024*1024
void Writelog(std::string strOutData)
{
	if (::PathFileExists(L"LogFlag"))
	{
		return;
	}

	//std::wstring wstrdata = L"";

	//for (int i = 0; i < g_LogData.size(); i++)
	//{
	//	wstrdata += g_LogData[i];
	//}

	//g_LogData.clear();
	//g_LogData.swap(std::vector<std::wstring>());

	DWORD dwCreationDisposition = OPEN_ALWAYS;

	HANDLE fileHandle = CreateFile(L"ZrDriver.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, NULL);
	if (NULL == fileHandle || fileHandle == INVALID_HANDLE_VALUE)
		return;

	if (g_isAutoCollect)
	{
		DWORD fileSize = 0;
		fileSize = GetFileSize(fileHandle,NULL);
		if (fileSize != INVALID_FILE_SIZE && fileSize >= LOGFILEMAXSIZE)
		{
			//dwCreationDisposition = TRUNCATE_EXISTING;

			SetFilePointer(fileHandle,0,NULL,FILE_BEGIN);
			SetEndOfFile(fileHandle);
		}
		else
		{
			SetFilePointer(fileHandle, 0, NULL, FILE_END);
		}
	}
	else
	{
		SetFilePointer(fileHandle, 0, NULL, FILE_END);
	}

	//if (dwCreationDisposition == OPEN_ALWAYS)
	//{
	//	SetFilePointer(fileHandle, 0, NULL, FILE_END);
	//}

	DWORD wirtebyte = 0;
	if (!WriteFile(fileHandle, strOutData.c_str(), strOutData.size(), &wirtebyte, NULL))
	{
		CloseHandle(fileHandle);
		fileHandle = NULL;
		return;
	}

	CloseHandle(fileHandle);
	fileHandle = NULL;

	//g_fileSize += len;
}

//获取数据
ULONG CdllMFCDlg::GetDriverData(HMODULE hModule)
{
	ULONG ret = -999;

	_GetMonitorMsg getMonitorMsg = 0;
	_FreeMonitorMsg freeMonitorMsg = 0;

	PMonitorMsg pMonitorMsg = NULL;
	ULONG msgNum = 0;

	if (!hModule)
		goto FINAL;

	getMonitorMsg = (_GetMonitorMsg)GetProcAddress(hModule, "GetMonitorMsg");
	freeMonitorMsg = (_FreeMonitorMsg)GetProcAddress(hModule, "FreeMonitorMsg");

	if (NULL == getMonitorMsg || NULL == freeMonitorMsg)
	{
		MessageBox(L"动态库获取函数失败失败");
		goto FINAL;
	}

	ret = SUCCESS;

	ret = getMonitorMsg(&pMonitorMsg, &msgNum);
	if (ret != SUCCESS || !pMonitorMsg)
		goto FINAL;

	PMonitorMsg p = pMonitorMsg;
	for (ULONG i = 0; i < msgNum; i++, p++)
	{
		PMonitorMsg pMsg = (PMonitorMsg)p;
		if (!pMsg)
			break;

		std::wstring wProcessPath = (LPWCH)pMsg->common.exe;
		std::string locale = "";
		std::string strProcessPath = wstring2string(wProcessPath, locale);

		time_t ts = pMsg->common.timestamp;
		char timeBuf[128];
		strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", localtime(&ts));

		std::string strOutData = FormatString("采集时间:%s 进程路径：%s,进程id:%d,父进程id:%d进程名:%s\r\n\t",
			timeBuf, strProcessPath.c_str(), pMsg->common.pid, pMsg->common.ppid,pMsg->common.comm);

		//Writelog(strOutData);

		switch (pMsg->common.type)
		{
		case Monitor_Process:
		{
			PPROCESSINFO pProcessInfo = (PPROCESSINFO)pMsg->data;

			if (pProcessInfo->processType == MT_ProcessCreate)
				strOutData += "[创建进程]";
			else if (pProcessInfo->processType == MT_ProcessExit)
				strOutData += "[退出进程]";
			else if (pProcessInfo->processType == MT_ProcessOpen)
				strOutData += "[打开进程]";
			else if (pProcessInfo->processType == MT_ProcessStart)
				strOutData += "[启动进程]";

			time_t createTs = pProcessInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			strOutData += FormatString("线程id:%d,进程创建时间:%s\r\n",
				pProcessInfo->threadId, createTimeBuf);

			Writelog(strOutData);

			//p += sizeof(MonitorMsg) + sizeof(PROCESSINFO);
			break;
		}
		case Monitor_Thread:
		{
			PTHREADINFO pThreadInfo = (PTHREADINFO)pMsg->data;

			if (pThreadInfo->threadType == MT_ThreadCreate)
				strOutData += "[创建线程]";
			else if (pThreadInfo->threadType == MT_ThreadExit)
				strOutData += "[退出线程]";
			else if (pThreadInfo->threadType == MT_ThreadOpen)
				strOutData += "[打开线程]";
			else if (pThreadInfo->threadType == MT_ThreadStart)
				strOutData += "[启动线程]";

			time_t createTs = pThreadInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			strOutData += FormatString("线程id:%d,进程创建时间:%s\r\n",
				pThreadInfo->threadId, createTimeBuf);

			Writelog(strOutData);

			//p += sizeof(MonitorMsg) + sizeof(THREADINFO);
			break;
		}
		case Monitor_File:
		{
			PFILEINFO pFileInfo = (PFILEINFO)pMsg->data;

			switch (pFileInfo->type)
			{
			case MT_FileCreate:
				strOutData += "[创建文件]";
				break;
			case MT_FileOpen:
				strOutData += "[打开文件]";
				break;
			case MT_FileClose:
				strOutData += "[关闭文件]";
				break;
			case MT_FileRead:
				strOutData += "[读取文件]";
				break;
			case MT_FileWrite:
				strOutData += "[写入文件]";
				break;
			case MT_FileDelete:
				strOutData += "[删除文件]";
				break;
			}

			std::wstring wFileName = pFileInfo->fileName;
			std::string locale = "";
			std::string strFilename = wstring2string(wFileName, locale);

			std::wstring wFilePath = pFileInfo->filePath;
			std::string strFilePath = wstring2string(wFilePath, locale);

			time_t createTs = pFileInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			time_t fileCreateTs = pFileInfo->fileCreateTime;
			char fileCreateTimeBuf[128] = { 0 };
			strftime(fileCreateTimeBuf, sizeof(fileCreateTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&fileCreateTs));

			strOutData += FormatString("线程id:%d,文件名:%s,文件路径:%s,进程创建时间:%s，文件创建时间:%s\r\n",
				pFileInfo->threadId, strFilename.c_str(), strFilePath.c_str(),
				createTimeBuf, fileCreateTimeBuf);

			Writelog(strOutData);

			//p += sizeof(MonitorMsg) + sizeof(FILEINFO);
			break;
		}
		case Monitor_Registry:
		{
			PREGISTERINFO pRegisterInfo = (PREGISTERINFO)pMsg->data;

			switch (pRegisterInfo->opearType)
			{
			case MT_RegCreateKey:
			{
				std::wstring wReName = pRegisterInfo->name;
				std::string strReName = wstring2string(wReName, locale);

				strOutData += "[创建注册表]名字:" + strReName + ",";
				break;
			}
			case MT_RegOpenKey:
			{
				std::wstring wReName = pRegisterInfo->name;
				std::string strReName = wstring2string(wReName, locale);

				strOutData += "[打开注册表]名字:" + strReName + ",";
				break;
			}
			case MT_RegDeleteKey:
				strOutData += "[删除注册表项]";
				break;
			case MT_RenameKey:
			{
				std::wstring wReName = pRegisterInfo->name;
				std::string strReName = wstring2string(wReName, locale);

				strOutData += "[重命名注册表项]名字:" + strReName + ",";
				break;
			}
			case MT_RegEnumKey:
			{
				std::wstring wReName = pRegisterInfo->name;
				std::string strReName = wstring2string(wReName, locale);

				strOutData += "[枚举注册表]名字:" + strReName + ",";
				break;
			}
			case MT_RegDeleteValue:
			{
				std::wstring wReName = pRegisterInfo->name;
				std::string strReName = wstring2string(wReName, locale);

				strOutData += "[删除注册表值]名字:" + strReName + ",";
				break;
			}
			case MT_RegSetValue:
			{
				std::wstring wReName = pRegisterInfo->name;
				std::string strReName = wstring2string(wReName, locale);

				std::string strData = pRegisterInfo->setData;

				strOutData += "[设置注册表值],项名:" + strReName + ",键值:" + strData;
				break;
			}

			case MT_RegQueryValue:
				strOutData += "[查询注册表值]";
				break;
			}

			std::wstring wObjectPath = pRegisterInfo->object;
			std::string strObjectPath = wstring2string(wObjectPath, locale);

			time_t createTs = pRegisterInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			strOutData += FormatString("线程id:%d,注册表路径:%s,进程创建时间:%s\r\n",
				pRegisterInfo->threadId, strObjectPath.c_str(),
				createTimeBuf);

			Writelog(strOutData);

			//p += sizeof(MonitorMsg) + sizeof(REGISTERINFO);
			break;
		}
		case Monitor_Socket:
		{	
			PNETWORKINFO pNetworkInfo = (PNETWORKINFO)pMsg->data;

			switch (pNetworkInfo->type)
			{
			case MT_SocketCreate:
				strOutData += "[创建网络]";
				break;
			case MT_SocketBind:
				strOutData += "[绑定网络端口]";
				break;
			case MT_SocketClose:
				strOutData += "[关闭网络]";
				break;
			case MT_SocketConnect:
				strOutData += "[连接网络]";
				break;
			case MT_SocketSend:
				strOutData += "[发送网络数据]";
				break;
			case MT_SocketRecv:
				strOutData += "[接收网络数据]";
				break;
			case MT_SocketAccept:
				strOutData += "[接收服务端网络数据]";
				break;
			}

			time_t createTs = pNetworkInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			strOutData += FormatString("线程id:%d,本地ip:%u.%u.%u.%u:%d;目的ip=%u.%u.%u.%u:%d,协议名:%S,进程创建时间:%s\r\n",
				pNetworkInfo->threadId,
				(pNetworkInfo->localIp >> 24) & 0xFF, (pNetworkInfo->localIp >> 16) & 0xFF, (pNetworkInfo->localIp >> 8) & 0xFF, pNetworkInfo->localIp & 0xFF,
				pNetworkInfo->localPort,
				(pNetworkInfo->remoteIP >> 24) & 0xFF, (pNetworkInfo->remoteIP >> 16) & 0xFF, (pNetworkInfo->remoteIP >> 8) & 0xFF, pNetworkInfo->remoteIP & 0xFF,
				pNetworkInfo->remotePort, pNetworkInfo->protocolName,
				createTimeBuf);

			Writelog(strOutData);

			//p += sizeof(MonitorMsg) + sizeof(NETWORKINFO);
			break;
		}
		case Monitor_USB:
		{
			PHOTPLUGINFO pHotPlugInfo = (PHOTPLUGINFO)pMsg->data;

			switch (pHotPlugInfo->type)
			{
			case MT_USBArrival:
				strOutData += "[USB插入]";
				break;
			case MT_USBRemoval:
				strOutData += "[USB移除]";
				break;
			}

			std::wstring wLinkName = pHotPlugInfo->symbolicLinkName;
			std::string locale = "";
			std::string strLinkName = wstring2string(wLinkName, locale);

			time_t createTs = pHotPlugInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			strOutData += FormatString("线程id:%d,名称:%s,进程创建时间:%s\r\n",
				pHotPlugInfo->threadId, strLinkName.c_str(),
				createTimeBuf);

			Writelog(strOutData);

			//p += sizeof(MonitorMsg) + sizeof(HOTPLUGINFO);
			break;
		}
		case Monitor_Image:
		{
			PLOADIMAGEINFO pLoadImageInfo = (PLOADIMAGEINFO)pMsg->data;

			std::wstring wImagePath = pLoadImageInfo->imagePath;
			std::string locale = "";
			std::string strImagePath = wstring2string(wImagePath, locale);

			time_t createTs = pLoadImageInfo->createTime;
			char createTimeBuf[128] = { 0 };
			strftime(createTimeBuf, sizeof(createTimeBuf), "%Y-%m-%d %H:%M:%S", localtime(&createTs));

			strOutData += FormatString("线程id:%d,模块路径:%s,模块大小:%d,进程创建时间:%s\r\n",
				pLoadImageInfo->threadId, strImagePath.c_str(), pLoadImageInfo->imageSize,
				createTimeBuf);

			Writelog(strOutData);
			break;
		}
		}
	}

FINAL:

	if (freeMonitorMsg)
	{
		freeMonitorMsg(pMonitorMsg, msgNum);
	}

	return ret;
}

//获取数据
void CdllMFCDlg::OnBnClickedButton7()
{
	ULONG ret = -999;
	HMODULE hModule = NULL;

	if (g_isAutoCollect)
	{
		MessageBox(L"请先关闭自动采集！");
		goto FINAL;
	}

	WCHAR dllName[255] = {0};
	GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(L"动态库为空");
		goto FINAL;
	}

	hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(L"动态库加载失败");
		goto FINAL;
	}

	m_getDataBt->EnableWindow(FALSE);

	ret = GetDriverData(hModule);

	m_getDataBt->EnableWindow(TRUE);
FINAL:
	if (ret != SUCCESS)
	{
		DWORD error = GetLastError();

		WCHAR tmp[24] = { 0 };
		wsprintf(tmp, L"获取数据失败:%s(%d)", GetErrorString(ret), error);

		MessageBox(tmp);
	}
	else
	{
		MessageBox(L"获取数据成功");
	}

	if (hModule)
	{
		FreeLibrary(hModule);
		hModule = NULL;
	}

	return;
}

#include "cJSON.h"
#include <vector>
BOOL ParseJsonFile(PVOID fileData,std::vector<std::wstring>* ForcessConfigs, std::vector<std::wstring>* fileConfigs)
{
	cJSON* root, *processItem, *fileItem = NULL;
	BOOL ret = FALSE;

	root = cJSON_Parse((char*)fileData);
	if (root == NULL)
		goto FINAL;

	ret = TRUE;
	processItem = cJSON_GetObjectItem(root,"Process");
	if (processItem == NULL)
		goto FINAL;

	int arraySize = cJSON_GetArraySize(processItem);
	for (int i = 0; i < arraySize; i++)
	{
		cJSON *item_array = cJSON_GetArrayItem(processItem, i);
		if (item_array->type != cJSON_String)
			continue;

		if (item_array->valuestring != NULL && item_array->valuestring[0] != '\0')
		{
			std::wstring wstr = L"";
			Utf8ToWchar(item_array->valuestring, wstr);
			if(!wstr.empty())
				ForcessConfigs->push_back(wstr);
		}	
	}

	fileItem = cJSON_GetObjectItem(root, "File");
	if (fileItem == NULL)
		goto FINAL;

	arraySize = cJSON_GetArraySize(fileItem);
	for (int i = 0; i < arraySize; i++)
	{
		cJSON *item_array = cJSON_GetArrayItem(fileItem, i);
		if (item_array->type != cJSON_String)
			continue;

		if (item_array->valuestring != NULL && item_array->valuestring[0] != '\0')
		{
			std::wstring wstr = L"";
			Utf8ToWchar(item_array->valuestring, wstr);
			if (!wstr.empty())
				fileConfigs->push_back(wstr);
		}
	}


FINAL:
	if (root)
	{
		cJSON_Delete(root);
		root = NULL;
	}

	return ret;
}

ULONG GetVectorDataSize(std::vector<std::wstring> configVector)
{
	ULONG dataSize = 0;
	for (int i = 0; i < configVector.size(); i++)
	{
		dataSize += configVector[i].size()*sizeof(WCHAR);
	}

	return dataSize;
}


BOOL CdllMFCDlg::GetFileData(LPWCH filePath, PVOID& fileData, PDWORD pFileSize)
{
	HANDLE fileHandle = NULL;
	BOOL ret = FALSE;
	if (!PathFileExists(filePath))
	{
		MessageBox(L"配置文件不存在");
		goto FINAL;
	}
	fileHandle = CreateFile(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!fileHandle)
	{
		MessageBox(L"打开文件失败");
		goto FINAL;
	}

	DWORD fileSize = 0;
	fileSize = GetFileSize(fileHandle, NULL);
	if (fileSize == 0 || fileSize == INVALID_FILE_SIZE)
	{
		MessageBox(L"获取文件大小失败");
		goto FINAL;
	}

	fileData = new byte[fileSize];
	memset(fileData, 0, fileSize);
	if (!ReadFile(fileHandle, fileData, fileSize, NULL, NULL))
	{
		MessageBox(L"读取文件失败");
		delete[] fileData;
		fileData = NULL;

		goto FINAL;
	}

	*pFileSize = fileSize;
	ret = TRUE;
FINAL:
	if (fileHandle)
	{
		CloseHandle(fileHandle);
		fileHandle = NULL;
	}
	return ret;
}

VOID CdllMFCDlg::GetConfigData(PVOID pConfigs)
{
	PULONG configs = (PULONG)pConfigs;

	if (m_isWhite->GetCheck())
	{
		configs[Monitor_Mode] = 1;
	}

	//进程开关
	if (m_processCheck->GetCheck())
	{
		configs[Monitor_Process] = 1;
	}

	if (m_processCreateCheck->GetCheck())
	{
		configs[MT_ProcessCreate] = 1;
	}
	if (m_processExitCheck->GetCheck())
	{
		configs[MT_ProcessExit] = 1;
	}
	if (m_processOpenCheck->GetCheck())
	{
		configs[MT_ProcessOpen] = 1;
	}
	if (m_processStartCheck->GetCheck())
	{
		configs[MT_ProcessStart] = 1;
	}

	//线程开关
	if (m_threadCheck->GetCheck())
	{
		configs[Monitor_Thread] = 1;
	}

	if (m_threadCreateCheck->GetCheck())
	{
		configs[MT_ThreadCreate] = 1;
	}
	if (m_threadExitCheck->GetCheck())
	{
		configs[MT_ThreadExit] = 1;
	}
	if (m_threadOpenCheck->GetCheck())
	{
		configs[MT_ThreadOpen] = 1;
	}
	if (m_threadStartCheck->GetCheck())
	{
		configs[MT_ThreadStart] = 1;
	}

	//文件开关
	if (m_fileCheck->GetCheck())
	{
		configs[Monitor_File] = 1;
	}

	if (m_fileCreateCheck->GetCheck())
	{
		configs[MT_FileCreate] = 1;
	}
	if (m_fileOpenCheck->GetCheck())
	{
		configs[MT_FileOpen] = 1;
	}
	if (m_fileCloseCheck->GetCheck())
	{
		configs[MT_FileClose] = 1;
	}
	if (m_fileReadCheck->GetCheck())
	{
		configs[MT_FileRead] = 1;
	}
	if (m_fileWriteCheck->GetCheck())
	{
		configs[MT_FileWrite] = 1;
	}
	if (m_fileDeleteCheck->GetCheck())
	{
		configs[MT_FileDelete] = 1;
	}

	//注册表开关
	if (m_registryCheck->GetCheck())
	{
		configs[Monitor_Registry] = 1;
	}

	if (m_registryCreateCheck->GetCheck())
	{
		configs[MT_RegCreateKey] = 1;
	}
	if (m_registryOpenCheck->GetCheck())
	{
		configs[MT_RegOpenKey] = 1;
	}
	if (m_registryDeleteKeyCheck->GetCheck())
	{
		configs[MT_RegDeleteKey] = 1;
	}
	if (m_registryRenameCheck->GetCheck())
	{
		configs[MT_RenameKey] = 1;
	}
	if (m_registryEnumCheck->GetCheck())
	{
		configs[MT_RegEnumKey] = 1;
	}
	if (m_registryDeleteValueCheck->GetCheck())
	{
		configs[MT_RegDeleteValue] = 1;
	}
	if (m_registrySetValueCheck->GetCheck())
	{
		configs[MT_RegSetValue] = 1;
	}
	if (m_registryQueryValueCheck->GetCheck())
	{
		configs[MT_RegQueryValue] = 1;
	}

	//网络开关
	if (m_socketCheck->GetCheck())
	{
		configs[Monitor_Socket] = 1;
	}

	if (m_socketCreateCheck->GetCheck())
	{
		configs[MT_SocketCreate] = 1;
	}
	if (m_socketBindCheck->GetCheck())
	{
		configs[MT_SocketBind] = 1;
	}
	if (m_socketCloseCheck->GetCheck())
	{
		configs[MT_SocketClose] = 1;
	}
	if (m_socketConnectCheck->GetCheck())
	{
		configs[MT_SocketConnect] = 1;
	}
	if (m_socketSendCheck->GetCheck())
	{
		configs[MT_SocketSend] = 1;
	}
	if (m_socketRevCheck->GetCheck())
	{
		configs[MT_SocketRecv] = 1;
	}
	if (m_socketAcceptCheck->GetCheck())
	{
		configs[MT_SocketAccept] = 1;
	}

	//USB开关
	if (m_hotplugCheck->GetCheck())
	{
		configs[Monitor_USB] = 1;
	}

	if (m_USBArrival->GetCheck())
	{
		configs[MT_USBArrival] = 1;
	}
	if (m_USBRemoval->GetCheck())
	{
		configs[MT_USBRemoval] = 1;
	}

	//模块加载开关
	if (m_loadimageCheck->GetCheck())
	{
		configs[Monitor_Image] = 1;
	}
}

//设置开关
void CdllMFCDlg::OnBnClickedButton10()
{
	WCHAR dllName[255] = { 0 };
	GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(L"动态库为空");
		return;
	}

	HMODULE hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(L"动态库加载失败");
		return;
	}

	_SetConfig sendConfig = (_SetConfig)GetProcAddress(hModule, "SetConfig");

	//_SendDriverIrp sendDriverIrp = (_SendDriverIrp)GetProcAddress(hModule, "SendDriverIrp");
	if (NULL == sendConfig)
	{
		FreeLibrary(hModule);
		hModule = NULL;
		MessageBox(L"动态库获取函数失败失败");
		return;
	}

	Config configs = { 0 };
	GetConfigData(&configs);

	ULONG ret = sendConfig(&configs);
	if (ret != SUCCESS)
	{
		FreeLibrary(hModule);
		hModule = NULL;

		DWORD error = GetLastError();
		WCHAR tmp[24] = { 0 };
		wsprintf(tmp, L"设置开关失败:%s(%d)", GetErrorString(ret), error);

		MessageBox(tmp);

		return;
	}

	FreeLibrary(hModule);
	hModule = NULL;

	MessageBox(L"设置成功");
}

VOID CdllMFCDlg::InitComboBox()
{
	m_policyComboBox = (CComboBox*)GetDlgItem(IDC_COMBO2);
	m_policyComboBox->AddString(L"进程");
	//m_policyComboBox->AddString(L"线程");
	m_policyComboBox->AddString(L"文件");
	//m_policyComboBox->AddString(L"注册表");
	//m_policyComboBox->AddString(L"网络");
	//m_policyComboBox->AddString(L"热插拔");

	m_policyOperationComboBox = (CComboBox*)GetDlgItem(IDC_COMBO3);
	m_policyOperationComboBox->AddString(L"添加");
	m_policyOperationComboBox->AddString(L"删除");
	m_policyOperationComboBox->AddString(L"清空");
}


VOID CdllMFCDlg::InitCheckBox()
{
	//自动采集开关
	m_autoCollectCheck = (CButton*)GetDlgItem(IDC_CHECK46);
	//自动采集
	m_autoCollectBt = (CButton*)GetDlgItem(IDC_BUTTON9);
	//关闭自动采集
	m_stopAutoCollectBt = (CButton*)GetDlgItem(IDC_BUTTON11);
	//获取数据
	m_getDataBt = (CButton*)GetDlgItem(IDC_BUTTON7);

	m_autoCollectBt->EnableWindow(FALSE);
	m_stopAutoCollectBt->EnableWindow(FALSE);


	m_allConfigCheck = (CButton*)GetDlgItem(IDC_CHECK1);
	//是否黑名单
	m_isBlack = (CButton*)GetDlgItem(IDC_CHECK2);
	//是否白名单
	m_isWhite = (CButton*)GetDlgItem(IDC_CHECK45);
	//进程开关
	m_processCheck = (CButton*)GetDlgItem(IDC_CHECK3);
	//线程开关
	m_threadCheck = (CButton*)GetDlgItem(IDC_CHECK4);
	//注册表开关
	m_registryCheck = (CButton*)GetDlgItem(IDC_CHECK6);
	//文件开关
	m_fileCheck = (CButton*)GetDlgItem(IDC_CHECK5);
	//网络开关
	m_socketCheck = (CButton*)GetDlgItem(IDC_CHECK7);
	//热插拔开关
	m_hotplugCheck = (CButton*)GetDlgItem(IDC_CHECK8);
	//模块加载开关
	m_loadimageCheck = (CButton*)GetDlgItem(IDC_CHECK48);

	//进程开关（全选）
	m_processAllCheck = (CButton*)GetDlgItem(IDC_CHECK41);
	//进程创建
	m_processCreateCheck = (CButton*)GetDlgItem(IDC_CHECK9);
	//进程打开
	m_processOpenCheck = (CButton*)GetDlgItem(IDC_CHECK11);
	//进程退出
	m_processExitCheck = (CButton*)GetDlgItem(IDC_CHECK10);
	//进程启动
	m_processStartCheck = (CButton*)GetDlgItem(IDC_CHECK12);

	//线程开关（全选）
	m_threadAllCheck = (CButton*)GetDlgItem(IDC_CHECK42);
	//线程创建
	m_threadCreateCheck = (CButton*)GetDlgItem(IDC_CHECK13);
	//线程打开
	m_threadOpenCheck = (CButton*)GetDlgItem(IDC_CHECK15);
	//线程退出
	m_threadExitCheck = (CButton*)GetDlgItem(IDC_CHECK14);
	//线程启动
	m_threadStartCheck = (CButton*)GetDlgItem(IDC_CHECK16);

	//注册表开关（全选）
	m_registryAllCheck = (CButton*)GetDlgItem(IDC_CHECK38);
	//注册表创建
	m_registryCreateCheck = (CButton*)GetDlgItem(IDC_CHECK17);
	//注册表打开
	m_registryOpenCheck = (CButton*)GetDlgItem(IDC_CHECK18);
	//注册表删除项
	m_registryDeleteKeyCheck = (CButton*)GetDlgItem(IDC_CHECK19);
	//注册表重命名
	m_registryRenameCheck = (CButton*)GetDlgItem(IDC_CHECK20);
	//注册表枚举
	m_registryEnumCheck = (CButton*)GetDlgItem(IDC_CHECK21);
	//注册表删除值
	m_registryDeleteValueCheck = (CButton*)GetDlgItem(IDC_CHECK22);
	//注册表设置值
	m_registrySetValueCheck = (CButton*)GetDlgItem(IDC_CHECK23);
	//注册表查询值
	m_registryQueryValueCheck = (CButton*)GetDlgItem(IDC_CHECK24);

	//文件开关（全选）
	m_fileAllCheck = (CButton*)GetDlgItem(IDC_CHECK39);
	//文件创建
	m_fileCreateCheck = (CButton*)GetDlgItem(IDC_CHECK25);
	//文件打开
	m_fileOpenCheck = (CButton*)GetDlgItem(IDC_CHECK26);
	//文件关闭
	m_fileCloseCheck = (CButton*)GetDlgItem(IDC_CHECK27);
	//文件读取
	m_fileReadCheck = (CButton*)GetDlgItem(IDC_CHECK28);
	//文件写入
	m_fileWriteCheck = (CButton*)GetDlgItem(IDC_CHECK29);
	//文件删除
	m_fileDeleteCheck = (CButton*)GetDlgItem(IDC_CHECK30);

	//网络开关（全选）
	m_socketAllCheck = (CButton*)GetDlgItem(IDC_CHECK40);
	//网络创建
	m_socketCreateCheck = (CButton*)GetDlgItem(IDC_CHECK31);
	//网络绑定端口
	m_socketBindCheck = (CButton*)GetDlgItem(IDC_CHECK32);
	//网络关闭
	m_socketCloseCheck = (CButton*)GetDlgItem(IDC_CHECK33);
	//网络连接
	m_socketConnectCheck = (CButton*)GetDlgItem(IDC_CHECK34);
	//网络发送
	m_socketSendCheck = (CButton*)GetDlgItem(IDC_CHECK35);
	//网络接收
	m_socketRevCheck = (CButton*)GetDlgItem(IDC_CHECK36);
	//网络服务端发送
	m_socketAcceptCheck = (CButton*)GetDlgItem(IDC_CHECK37);

	//USB全选开关
	m_USBAllCheck = (CButton*)GetDlgItem(IDC_CHECK47);
	//USB插入
	m_USBArrival = (CButton*)GetDlgItem(IDC_CHECK43);
	//USB拔出
	m_USBRemoval = (CButton*)GetDlgItem(IDC_CHECK44);

	m_isWhite->SetCheck(TRUE);

	m_autoCollectBt->EnableWindow(TRUE);
	m_stopAutoCollectBt->EnableWindow(TRUE);


	m_processCheck->EnableWindow(TRUE);
	m_threadCheck->EnableWindow(TRUE);
	m_registryCheck->EnableWindow(TRUE);
	m_fileCheck->EnableWindow(TRUE);
	m_socketCheck->EnableWindow(TRUE);
	m_hotplugCheck->EnableWindow(TRUE);
	m_loadimageCheck->EnableWindow(TRUE);

	InitProcessCheckBox();
	InitThreadCheckBox();
	InitFileCheckBox();
	InitRegistryCheckBox();
	InitSocketCheckBox();
	InitUSBCheckBox();
}

VOID CdllMFCDlg::InitProcessCheckBox()
{
	m_processAllCheck->EnableWindow(FALSE);
	m_processAllCheck->SetCheck(FALSE);

	SetProcessConfigDisable(FALSE);
}

VOID CdllMFCDlg::InitThreadCheckBox()
{
	m_threadAllCheck->EnableWindow(FALSE);
	m_threadAllCheck->SetCheck(FALSE);

	SetThreadConfigDisable(FALSE);
}

VOID CdllMFCDlg::InitFileCheckBox()
{
	m_fileAllCheck->EnableWindow(FALSE);
	m_fileAllCheck->SetCheck(FALSE);

	SetFileConfigDisable(FALSE);
}

VOID CdllMFCDlg::InitRegistryCheckBox()
{
	m_registryAllCheck->EnableWindow(FALSE);
	m_registryAllCheck->SetCheck(FALSE);

	SetRegistryConfigDisable(FALSE);
}

VOID CdllMFCDlg::InitSocketCheckBox()
{
	m_socketAllCheck->EnableWindow(FALSE);
	m_socketAllCheck->SetCheck(FALSE);

	SetSocketConfigDisable(FALSE);
}

VOID CdllMFCDlg::InitUSBCheckBox()
{
	m_USBAllCheck->EnableWindow(FALSE);
	m_USBAllCheck->SetCheck(FALSE);

	SetUSBConfigDisable(FALSE);
}


//设置开关是否可编辑
VOID CdllMFCDlg::SetProcessConfigDisable(BOOL isDisable)
{
	//进程开关（全选）
	//m_processAllCheck->EnableWindow(isDisable);
	//进程创建
	m_processCreateCheck->EnableWindow(isDisable);
	//进程打开
	m_processOpenCheck->EnableWindow(isDisable);
	//进程退出
	m_processExitCheck->EnableWindow(isDisable);
	//进程启动
	m_processStartCheck->EnableWindow(isDisable);
}

VOID CdllMFCDlg::SetThreadConfigDisable(BOOL isDisable)
{
	//线程开关（全选）
	//m_threadAllCheck->EnableWindow(isDisable);
	//线程创建
	m_threadCreateCheck->EnableWindow(isDisable);
	//线程打开
	m_threadOpenCheck->EnableWindow(isDisable);
	//线程退出
	m_threadExitCheck->EnableWindow(isDisable);
	//线程启动
	m_threadStartCheck->EnableWindow(isDisable);
}

VOID CdllMFCDlg::SetFileConfigDisable(BOOL isDisable)
{
	//文件开关（全选）
	//m_fileAllCheck->EnableWindow(isDisable);
	//文件创建
	m_fileCreateCheck->EnableWindow(isDisable);
	//文件打开
	m_fileOpenCheck->EnableWindow(isDisable);
	//文件关闭
	m_fileCloseCheck->EnableWindow(isDisable);
	//文件读取
	m_fileReadCheck->EnableWindow(isDisable);
	//文件写入
	m_fileWriteCheck->EnableWindow(isDisable);
	//文件删除
	m_fileDeleteCheck->EnableWindow(isDisable);
}

VOID CdllMFCDlg::SetRegistryConfigDisable(BOOL isDisable)
{
	//注册表开关（全选）
	//m_registryAllCheck->EnableWindow(isDisable);
	//注册表创建
	m_registryCreateCheck->EnableWindow(isDisable);
	//注册表打开
	m_registryOpenCheck->EnableWindow(isDisable);
	//注册表删除项
	m_registryDeleteKeyCheck->EnableWindow(isDisable);
	//注册表重命名
	m_registryRenameCheck->EnableWindow(isDisable);
	//注册表枚举
	m_registryEnumCheck->EnableWindow(isDisable);
	//注册表删除值
	m_registryDeleteValueCheck->EnableWindow(isDisable);
	//注册表设置值
	m_registrySetValueCheck->EnableWindow(isDisable);
	//注册表查询值
	m_registryQueryValueCheck->EnableWindow(isDisable);
}

VOID CdllMFCDlg::SetSocketConfigDisable(BOOL isDisable)
{
	//网络开关（全选）
	//m_socketAllCheck->EnableWindow(isDisable);
	//网络创建
	m_socketCreateCheck->EnableWindow(isDisable);
	//网络绑定端口
	m_socketBindCheck->EnableWindow(isDisable);
	//网络关闭
	m_socketCloseCheck->EnableWindow(isDisable);
	//网络连接
	m_socketConnectCheck->EnableWindow(isDisable);
	//网络发送
	m_socketSendCheck->EnableWindow(isDisable);
	//网络接收
	m_socketRevCheck->EnableWindow(isDisable);
	//网络服务端发送
	m_socketAcceptCheck->EnableWindow(isDisable);
}

VOID CdllMFCDlg::SetUSBConfigDisable(BOOL isDisable)
{
	//USB开关（全选）
	//m_USBAllCheck->EnableWindow(isDisable);
	//USB插入
	m_USBArrival->EnableWindow(isDisable);
	//USB拔出
	m_USBRemoval->EnableWindow(isDisable);
}


VOID CdllMFCDlg::SetAllCheck(BOOL isDisable)
{
	m_processCheck->SetCheck(isDisable);
	m_threadCheck->SetCheck(isDisable);
	m_registryCheck->SetCheck(isDisable);
	m_fileCheck->SetCheck(isDisable);
	m_socketCheck->SetCheck(isDisable);
	m_hotplugCheck->SetCheck(isDisable);
	m_loadimageCheck->SetCheck(isDisable);
}

VOID CdllMFCDlg::SetProcessCheck(BOOL isDisable)
{
	//进程创建
	m_processCreateCheck->SetCheck(isDisable);
	//进程打开
	m_processOpenCheck->SetCheck(isDisable);
	//进程退出
	m_processExitCheck->SetCheck(isDisable);
	//进程启动
	m_processStartCheck->SetCheck(isDisable);
}

VOID CdllMFCDlg::SetThreadCheck(BOOL isDisable)
{
	//线程创建
	m_threadCreateCheck->SetCheck(isDisable);
	//线程打开
	m_threadOpenCheck->SetCheck(isDisable);
	//线程退出
	m_threadExitCheck->SetCheck(isDisable);
	//线程启动
	m_threadStartCheck->SetCheck(isDisable);
}

VOID CdllMFCDlg::SetFileCheck(BOOL isDisable)
{
	//文件创建
	m_fileCreateCheck->SetCheck(isDisable);
	//文件打开
	m_fileOpenCheck->SetCheck(isDisable);
	//文件关闭
	m_fileCloseCheck->SetCheck(isDisable);
	//文件读取
	m_fileReadCheck->SetCheck(isDisable);
	//文件写入
	m_fileWriteCheck->SetCheck(isDisable);
	//文件删除
	m_fileDeleteCheck->SetCheck(isDisable);

}

VOID CdllMFCDlg::SetRegistryCheck(BOOL isDisable)
{
	//注册表创建
	m_registryCreateCheck->SetCheck(isDisable);
	//注册表打开
	m_registryOpenCheck->SetCheck(isDisable);
	//注册表删除项
	m_registryDeleteKeyCheck->SetCheck(isDisable);
	//注册表重命名
	m_registryRenameCheck->SetCheck(isDisable);
	//注册表枚举
	m_registryEnumCheck->SetCheck(isDisable);
	//注册表删除值
	m_registryDeleteValueCheck->SetCheck(isDisable);
	//注册表设置值
	m_registrySetValueCheck->SetCheck(isDisable);
	//注册表查询值
	m_registryQueryValueCheck->SetCheck(isDisable);
}

VOID CdllMFCDlg::SetSocketCheck(BOOL isDisable)
{
	//网络创建
	m_socketCreateCheck->SetCheck(isDisable);
	//网络绑定端口
	m_socketBindCheck->SetCheck(isDisable);
	//网络关闭
	m_socketCloseCheck->SetCheck(isDisable);
	//网络连接
	m_socketConnectCheck->SetCheck(isDisable);
	//网络发送
	m_socketSendCheck->SetCheck(isDisable);
	//网络接收
	m_socketRevCheck->SetCheck(isDisable);
	//网络服务端发送
	m_socketAcceptCheck->SetCheck(isDisable);
}

VOID CdllMFCDlg::SetUSBCheck(BOOL isDisable)
{
	//USB插入
	m_USBArrival->SetCheck(isDisable);
	//USB拔出
	m_USBRemoval->SetCheck(isDisable);
}




//===================================================

#include <windows.h>
#include<psapi.h>

__int64 CompareFileTime(FILETIME time1, FILETIME time2)
{
	__int64 a = time1.dwHighDateTime << 32 | time1.dwLowDateTime;
	__int64 b = time2.dwHighDateTime << 32 | time2.dwLowDateTime;
	return (b - a);
}
VOID GetCpuUsage(LPWCH outData, ULONG dataSize)
{
	if (NULL == outData || dataSize == 0)
		return;

	static FILETIME preidleTime;
	static FILETIME prekernelTime;
	static FILETIME preuserTime;

	// 空闲时间
	FILETIME idle_time;
	// 内核时间
	FILETIME kernel_time;
	// 用户时间
	FILETIME user_time;
	BOOL ret = GetSystemTimes(&idle_time, &kernel_time, &user_time);

	//运行时间 = 内核时间 + 用户时间 - 空闲时间
	//间隔时间 = 内核时间 + 用户时间
	//CPU使用率% = 运行时间 / 间隔时间

	preidleTime = idle_time;
	prekernelTime = kernel_time;
	preuserTime = user_time;
	
	Sleep(1000);
	ret = GetSystemTimes(&idle_time, &kernel_time, &user_time);

	// 一秒内的cup空闲时间
	ULONG idle = CompareFileTime(preidleTime,idle_time);
	// 一秒内内核进程cup的占用时间
	ULONG kernel = CompareFileTime(prekernelTime,kernel_time);
	// 一秒内用户进程占用cpu的时间
	ULONG user = CompareFileTime(preuserTime,user_time);
	// （总的时间-空闲时间） / 总的时间 = 占用cpu时间的使用率
	int cpuUsage = (kernel + user - idle) *100.0 / (kernel + user);
	int cpuidle = (idle) *100.0 / (kernel + user);

	preidleTime = idle_time;
	prekernelTime = kernel_time;
	preuserTime = user_time;

	swprintf(outData,L"CPU:%d%%\n", cpuUsage);

}

//typedef struct _PROCESS_MEMORY_COUNTERS {
//	DWORD cb;
//	DWORD PageFaultCount;
//	SIZE_T PeakWorkingSetSize;           //峰值内存使用
//	SIZE_T WorkingSetSize;               //内存使用
//	SIZE_T QuotaPeakPagedPoolUsage;
//	SIZE_T QuotaPagedPoolUsage;
//	SIZE_T QuotaPeakNonPagedPoolUsage;
//	SIZE_T QuotaNonPagedPoolUsage;
//	SIZE_T PagefileUsage;               //虚拟内存使用
//	SIZE_T PeakPagefileUsage;           //峰值虚拟内存使用
//} PROCESS_MEMORY_COUNTERS,
//*PPROCESS_MEMORY_COUNTERS;

//void GetMemoryInfo(DWORD processID)
//{
//	HANDLE hProcess;
//	PROCESS_MEMORY_COUNTERS pmc;
//
//	printf("\nProcess ID: %u\n", processID);
//
//	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
//		PROCESS_VM_READ,
//		FALSE, processID);
//	if (NULL == hProcess)
//		return;
//
//	if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
//	{
//		printf("\tPageFaultCount: 0x%08X\n", pmc.PageFaultCount);
//		printf("\tPeakWorkingSetSize: 0x%08X\n",
//			pmc.PeakWorkingSetSize);
//		printf("\tWorkingSetSize: 0x%08X\n", pmc.WorkingSetSize);
//		printf("\tQuotaPeakPagedPoolUsage: 0x%08X\n",
//			pmc.QuotaPeakPagedPoolUsage);
//		printf("\tQuotaPagedPoolUsage: 0x%08X\n",
//			pmc.QuotaPagedPoolUsage);
//		printf("\tQuotaPeakNonPagedPoolUsage: 0x%08X\n",
//			pmc.QuotaPeakNonPagedPoolUsage);
//		printf("\tQuotaNonPagedPoolUsage: 0x%08X\n",
//			pmc.QuotaNonPagedPoolUsage);
//		printf("\tPagefileUsage: 0x%08X\n", pmc.PagefileUsage);
//		printf("\tPeakPagefileUsage: 0x%08X\n",
//			pmc.PeakPagefileUsage);
//	}
//
//	CloseHandle(hProcess);
//}

//获取系统总内存
VOID GetSystemMemory(LPWCH outData,ULONG dataSize)
{
	if (NULL == outData || dataSize == 0)
		return;

	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&memInfo);

	swprintf(outData,L"allMemory:%IdMB\tIdleMemory:%IdMB\t% Id%%\n", 
		memInfo.ullTotalPhys / 1024 / 1024, memInfo.ullAvailPhys/1024/1024,
		(memInfo.ullTotalPhys- memInfo.ullAvailPhys)*100/ memInfo.ullTotalPhys);
	
	return;

	/*DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return;
	}

	cProcesses = cbNeeded / sizeof(DWORD);
	for (i = 0; i < cProcesses; i++)
	{
		GetMemoryInfo(aProcesses[i]);
	}*/
}

void WriteSystemInfo(LPWCH data)
{
	if (NULL == data || data[0] == L'\0')
		return;

	DWORD wirtebyte = 0;
	

	HANDLE fileHandle = CreateFile(L"SystemInfo.log", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (NULL == fileHandle || fileHandle == INVALID_HANDLE_VALUE)
		return;

	SetFilePointer(fileHandle, 0, NULL, FILE_END);
	
	
	ULONG len = lstrlen(data);
	if (!WriteFile(fileHandle, data, len * sizeof(WCHAR), &wirtebyte, NULL))
	{
		CloseHandle(fileHandle);
		fileHandle = NULL;
		return;
	}

	CloseHandle(fileHandle);
	fileHandle = NULL;
}

DWORD WINAPI CollectSystemInfoThread(LPVOID param)
{
	ULONG pcollectTime = *(ULONG*)param;

	time_t beginTm = time(0);
	while (TRUE)
	{
		if ((time(0) - beginTm) < pcollectTime)
		{
			Sleep(10000);
			continue;
		}

		WCHAR cpuUage[48] = { 0 };
		GetCpuUsage(cpuUage, 48);

		WCHAR systemMemory[1024] = { 0 };
		GetSystemMemory(systemMemory, 1024);

		WCHAR outData[2048] = { 0 };

		time_t nowTime = time(0);
		tm* tp = localtime(&nowTime);

		swprintf(outData,L"%04d-%02d-%02d %02d:%02d:%02d %s%s",
			tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday,
			tp->tm_hour, tp->tm_min, tp->tm_sec,
			cpuUage,systemMemory);

		WriteSystemInfo(outData);
		
		beginTm = time(0);
	}
}

//系统资源采集
void CdllMFCDlg::OnBnClickedButton13()
{
	ULONG collectTime = 10 * 60;

	WCHAR wCollectTime[255] = { 0 };
	GetDlgItemText(IDC_EDIT4, wCollectTime, 254);
	if (wCollectTime[0] == '\0')
	{
		MessageBox(L"资源采集间隔为空，默认1小时");
	}

	collectTime = _wtoi(wCollectTime);

	//g_IsCollectSystemThreadEnd
	HANDLE hThrad = CreateThread(NULL,0, CollectSystemInfoThread,(LPVOID)&collectTime,0,0);
	if (!hThrad)
	{
		MessageBox(L"创建系统采集线程失败");
	}
}

//进程开关
void CdllMFCDlg::OnBnClickedCheck3()
{
	if (m_processCheck->GetCheck())
	{
		m_processAllCheck->EnableWindow(TRUE);
		SetProcessConfigDisable(TRUE);
	}
	else
	{
		InitProcessCheckBox();
		SetProcessConfigDisable(FALSE);
		SetProcessCheck(FALSE);
	}
}

//线程开关
void CdllMFCDlg::OnBnClickedCheck4()
{
	if (m_threadCheck->GetCheck())
	{
		m_threadAllCheck->EnableWindow(TRUE);
		SetThreadConfigDisable(TRUE);
	}
	else
	{
		InitThreadCheckBox();
		SetThreadConfigDisable(FALSE);
		SetThreadCheck(FALSE);
	}
}

//注册表开关
void CdllMFCDlg::OnBnClickedCheck6()
{
	if (m_registryCheck->GetCheck())
	{
		m_registryAllCheck->EnableWindow(TRUE);
		SetRegistryConfigDisable(TRUE);
	}
	else
	{
		InitRegistryCheckBox();
		SetRegistryConfigDisable(FALSE);
		SetRegistryCheck(FALSE);
	}
}

//文件开关
void CdllMFCDlg::OnBnClickedCheck5()
{
	if (m_fileCheck->GetCheck())
	{
		m_fileAllCheck->EnableWindow(TRUE);
		SetFileConfigDisable(TRUE);
	}
	else
	{
		InitFileCheckBox();
		SetFileConfigDisable(FALSE);
		SetFileCheck(FALSE);
	}
}

//网络开关
void CdllMFCDlg::OnBnClickedCheck7()
{
	if (m_socketCheck->GetCheck())
	{
		m_socketAllCheck->EnableWindow(TRUE);
		SetSocketConfigDisable(TRUE);
	}
	else
	{
		InitSocketCheckBox();
		SetSocketConfigDisable(FALSE);
		SetSocketCheck(FALSE);
	}
}

//进程全选
void CdllMFCDlg::OnBnClickedCheck41()
{
	if (m_processAllCheck->GetCheck())
	{
		SetProcessCheck(TRUE);
	}
	else
	{
		SetProcessCheck(FALSE);
	}
}

//线程全选
void CdllMFCDlg::OnBnClickedCheck42()
{
	if (m_threadAllCheck->GetCheck())
	{
		SetThreadCheck(TRUE);
	}
	else
	{
		SetThreadCheck(FALSE);
	}
}

//注册表全选
void CdllMFCDlg::OnBnClickedCheck38()
{
	if (m_registryAllCheck->GetCheck())
	{
		SetRegistryCheck(TRUE);
	}
	else
	{
		SetRegistryCheck(FALSE);
	}
}

//文件全选
void CdllMFCDlg::OnBnClickedCheck39()
{
	if (m_fileAllCheck->GetCheck())
	{
		SetFileCheck(TRUE);
	}
	else
	{
		SetFileCheck(FALSE);
	}
}

//网络全选
void CdllMFCDlg::OnBnClickedCheck40()
{
	if (m_socketAllCheck->GetCheck())
	{
		SetSocketCheck(TRUE);
	}
	else
	{
		SetSocketCheck(FALSE);
	}
}

PolicyType_EM GetMonitorType(CString polictType)
{
	if (polictType.IsEmpty())
		return POLICY_EXE_LIST;

	if (polictType.Compare(L"进程") == 0)
	{
		return POLICY_EXE_LIST;
	}
	//else if (polictType.Compare(L"线程") == 0)
	//{
	//	return Monitor_Thread;
	//}
	else if (polictType.Compare(L"文件") == 0)
	{
		return POLICY_FILE_LIST;
	}
	//else if (polictType.Compare(L"注册表") == 0)
	//{
	//	return Monitor_Registry;
	//}
	//else if (polictType.Compare(L"网络") == 0)
	//{
	//	return Monitor_Socket;
	//}
	//else if (polictType.Compare(L"热插拔") == 0)
	//{
	//	return Monitor_USB;
	//}

	return POLICY_EXE_LIST;
}


//设置配置
void CdllMFCDlg::OnBnClickedButton8()
{
	WCHAR dllName[255] = { 0 };
	GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(L"动态库为空");
		return;
	}

	int curIndex = m_policyOperationComboBox->GetCurSel();
	if (curIndex < 0)
	{
		MessageBox(L"请选择配置类型");
		return;
	}
	CString polictOperation;
	m_policyOperationComboBox->GetLBText(curIndex, polictOperation);

	int curPolicyIndex = m_policyComboBox->GetCurSel();
	if (curPolicyIndex < 0)
	{
		MessageBox(L"请选择配置项");
		return;
	}

	CString polictType;
	m_policyComboBox->GetLBText(curPolicyIndex, polictType);
	
	Policy policyData;
	policyData.type = GetMonitorType(polictType);

	if (polictOperation.Compare(L"清空") == 0)
	{
		policyData.operation = CLR;
	}
	else
	{
		if (polictOperation.Compare(L"删除") == 0)
		{
			policyData.operation = DEL;
		}
		else if (polictOperation.Compare(L"添加") == 0)
		{
			policyData.operation = ADD;
		}

		WCHAR policyEditData[255] = { 0 };
		GetDlgItemText(IDC_EDIT5, policyEditData, 254);
		if (policyEditData[0] == L'\0')
		{
			MessageBox(L"配置数据为空");
			return;
		}

		std::wstring wpolicyEditData = policyEditData;
		std::string locale = "";
		std::string strpolicyData = wstring2string(wpolicyEditData, locale);

		ULONG dataSize = strpolicyData.size() > 1024 ? 1024 : strpolicyData.size();
		RtlZeroMemory(policyData.data, 512);
		RtlCopyMemory(policyData.data, strpolicyData.c_str(), dataSize);
	}

	HMODULE hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(L"动态库加载失败");
		return;
	}

	_SetPolicy setpolicy = (_SetPolicy)GetProcAddress(hModule, "SetPolicy");

	if (NULL == setpolicy)
	{
		FreeLibrary(hModule);
		hModule = NULL;
		MessageBox(L"动态库获取函数失败失败");
		return;
	}

	ULONG ret = setpolicy(&policyData);
	if (ret != 0)
	{
		FreeLibrary(hModule);
		hModule = NULL;

		DWORD error = GetLastError();
		WCHAR tmp[24] = { 0 };
		wsprintf(tmp, L"设置失败:%s(%d)", GetErrorString(ret),error);

		MessageBox(tmp);

		return;
	}

	MessageBox(L"设置成功");

	FreeLibrary(hModule);
	hModule = NULL;
	return;
}

//全选
void CdllMFCDlg::OnBnClickedCheck1()
{
	if (m_allConfigCheck->GetCheck())
	{
		//m_isWhite->SetCheck(TRUE);

		SetAllCheck(TRUE);

		SetProcessConfigDisable(TRUE);
		SetThreadConfigDisable(TRUE);
		SetFileConfigDisable(TRUE);
		SetRegistryConfigDisable(TRUE);
		SetSocketConfigDisable(TRUE);
		SetUSBConfigDisable(TRUE);

		m_processAllCheck->EnableWindow(TRUE);
		m_threadAllCheck->EnableWindow(TRUE);
		m_fileAllCheck->EnableWindow(TRUE);
		m_registryAllCheck->EnableWindow(TRUE);
		m_socketAllCheck->EnableWindow(TRUE);
		m_USBAllCheck->EnableWindow(TRUE);

		m_processAllCheck->SetCheck(TRUE);
		m_threadAllCheck->SetCheck(TRUE);
		m_fileAllCheck->SetCheck(TRUE);
		m_registryAllCheck->SetCheck(TRUE);
		m_socketAllCheck->SetCheck(TRUE);
		m_USBAllCheck->SetCheck(TRUE);

		//m_processCheck->EnableWindow(TRUE);
		//m_threadCheck->EnableWindow(TRUE);
		//m_registryCheck->EnableWindow(TRUE);
		//m_fileCheck->EnableWindow(TRUE);
		//m_socketCheck->EnableWindow(TRUE);
		//m_hotplugCheck->EnableWindow(TRUE);

		m_processCheck->SetCheck(TRUE);
		m_threadCheck->SetCheck(TRUE);
		m_registryCheck->SetCheck(TRUE);
		m_fileCheck->SetCheck(TRUE);
		m_socketCheck->SetCheck(TRUE);
		m_hotplugCheck->SetCheck(TRUE);
		m_loadimageCheck->SetCheck(TRUE);

		SetProcessCheck(TRUE);
		SetThreadCheck(TRUE);
		SetRegistryCheck(TRUE);
		SetFileCheck(TRUE);
		SetSocketCheck(TRUE);
		SetUSBCheck(TRUE);
	}
	else
	{
		//m_isWhite->SetCheck(FALSE);

		SetAllCheck(FALSE);

		SetProcessConfigDisable(FALSE);
		SetThreadConfigDisable(FALSE);
		SetFileConfigDisable(FALSE);
		SetRegistryConfigDisable(FALSE);
		SetSocketConfigDisable(FALSE);
		SetUSBConfigDisable(FALSE);

		m_processAllCheck->EnableWindow(FALSE);
		m_threadAllCheck->EnableWindow(FALSE);
		m_fileAllCheck->EnableWindow(FALSE);
		m_registryAllCheck->EnableWindow(FALSE);
		m_socketAllCheck->EnableWindow(FALSE);
		m_USBAllCheck->EnableWindow(FALSE);

		m_processAllCheck->SetCheck(FALSE);
		m_threadAllCheck->SetCheck(FALSE);
		m_fileAllCheck->SetCheck(FALSE);
		m_registryAllCheck->SetCheck(FALSE);
		m_socketAllCheck->SetCheck(FALSE);
		m_USBAllCheck->SetCheck(FALSE);

		//m_processCheck->EnableWindow(FALSE);
		//m_threadCheck->EnableWindow(FALSE);
		//m_registryCheck->EnableWindow(FALSE);
		//m_fileCheck->EnableWindow(FALSE);
		//m_socketCheck->EnableWindow(FALSE);
		//m_hotplugCheck->EnableWindow(FALSE);

		m_processCheck->SetCheck(FALSE);
		m_threadCheck->SetCheck(FALSE);
		m_registryCheck->SetCheck(FALSE);
		m_fileCheck->SetCheck(FALSE);
		m_socketCheck->SetCheck(FALSE);
		m_hotplugCheck->SetCheck(FALSE);
		m_loadimageCheck->SetCheck(FALSE);


		SetProcessCheck(FALSE);
		SetThreadCheck(FALSE);
		SetRegistryCheck(FALSE);
		SetFileCheck(FALSE);
		SetSocketCheck(FALSE);
		SetUSBCheck(FALSE);
	}
}

#define Rc4Key "XyDriverRc4Key"
//转换配置文件
void CdllMFCDlg::OnBnClickedButton2()
{
	BOOL ret = FALSE;
	HANDLE hFileHandle = NULL;
	HANDLE hOutFileHandle = NULL;
	PBYTE fileData = NULL;

	std::wstring newConfigPath = L"";

	WCHAR configPath[255] = { 0 };
	GetDlgItemText(IDC_EDIT3, configPath, 254);
	if (configPath[0] == L'\0')
	{
		MessageBox(L"配置文件为空");
		return;
	}

	if (!PathFileExists(configPath))
	{
		goto FINAL;
	}

	hFileHandle = CreateFile(configPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

	//加密
	BYTE rcKey[512] = { 0 };
	int keyLen = strlen(Rc4Key);
	rc4_set_key(rcKey, (PBYTE)Rc4Key, keyLen);
	rc4_transform(rcKey, fileData, fileSize);

	DWORD rscLen = fileSize * 2;
	PBYTE rsc_buf = new BYTE[rscLen];;
	hex_asc(fileData, rsc_buf, fileSize);

	newConfigPath = configPath;
	DWORD lastOffset = newConfigPath.find_last_of(L"\\");
	if (lastOffset == -1)
	{
		goto FINAL;
	}

	newConfigPath = newConfigPath.substr(0, lastOffset + 1) + L"driver.json";

	hOutFileHandle = CreateFile(newConfigPath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFileHandle == INVALID_HANDLE_VALUE)
	{
		goto FINAL;
	}

	if (!WriteFile(hOutFileHandle, rsc_buf, rscLen, &retSize, NULL))
	{
		goto FINAL;
	}

	ret = TRUE;

FINAL:
	if (hFileHandle)
	{
		CloseHandle(hFileHandle);
		hFileHandle = NULL;
	}

	if (hOutFileHandle)
	{
		CloseHandle(hOutFileHandle);
		hOutFileHandle = NULL;
	}

	if (fileData)
	{
		delete[] fileData;
		fileData = NULL;
	}

	if (ret)
	{
		WCHAR tmp[512] = { 0 };
		swprintf(tmp,L"文件路径:%s", newConfigPath.c_str());
		MessageBox(tmp);
	}
	else
	{
		MessageBox(L"加密文件失败");
	}
	return;

}


void CdllMFCDlg::OnBnClickedCheck47()
{
	if (m_USBAllCheck->GetCheck())
	{
		SetUSBCheck(TRUE);
	}
	else
	{
		SetUSBCheck(FALSE);
	}
}

//USB开关
void CdllMFCDlg::OnBnClickedCheck8()
{
	if (m_hotplugCheck->GetCheck())
	{
		m_USBAllCheck->EnableWindow(TRUE);
		SetUSBConfigDisable(TRUE);
	}
	else
	{
		InitUSBCheckBox();
		SetUSBConfigDisable(FALSE);
		SetUSBCheck(FALSE);
	}
}

//黑名单开关
void CdllMFCDlg::OnBnClickedCheck2()
{
	if (m_isBlack->GetCheck())
	{
		m_isWhite->SetCheck(FALSE);
	}
	else
	{
		m_isWhite->SetCheck(TRUE);
	}

	//if (m_isWhite->GetCheck())
	//{
	//	SetProcessConfigDisable(FALSE);
	//	SetThreadConfigDisable(FALSE);
	//	SetFileConfigDisable(FALSE);
	//	SetRegistryConfigDisable(FALSE);
	//	SetSocketConfigDisable(FALSE);

	//	m_processAllCheck->EnableWindow(FALSE);
	//	m_threadAllCheck->EnableWindow(FALSE);
	//	m_fileAllCheck->EnableWindow(FALSE);
	//	m_registryAllCheck->EnableWindow(FALSE);
	//	m_socketAllCheck->EnableWindow(FALSE);

	//	m_processCheck->EnableWindow(TRUE);
	//	m_threadCheck->EnableWindow(TRUE);
	//	m_registryCheck->EnableWindow(TRUE);
	//	m_fileCheck->EnableWindow(TRUE);
	//	m_socketCheck->EnableWindow(TRUE);
	//	m_hotplugCheck->EnableWindow(TRUE);
	//}
	//else
	//{
	//	SetAllCheck(FALSE);
	//	m_processCheck->EnableWindow(FALSE);
	//	m_threadCheck->EnableWindow(FALSE);
	//	m_registryCheck->EnableWindow(FALSE);
	//	m_fileCheck->EnableWindow(FALSE);
	//	m_socketCheck->EnableWindow(FALSE);
	//	m_hotplugCheck->EnableWindow(FALSE);

	//	InitProcessCheckBox();
	//	SetProcessConfigDisable(FALSE);
	//	SetProcessCheck(FALSE);

	//	InitThreadCheckBox();
	//	SetThreadConfigDisable(FALSE);
	//	SetThreadCheck(FALSE);

	//	InitRegistryCheckBox();
	//	SetRegistryConfigDisable(FALSE);
	//	SetRegistryCheck(FALSE);

	//	InitFileCheckBox();
	//	SetFileConfigDisable(FALSE);
	//	SetFileCheck(FALSE);

	//	InitSocketCheckBox();
	//	SetSocketConfigDisable(FALSE);
	//	SetSocketCheck(FALSE);

	//	InitUSBCheckBox();
	//	SetUSBConfigDisable(FALSE);
	//	SetUSBCheck(FALSE);
	//}
}

//白名单开关
void CdllMFCDlg::OnBnClickedCheck45()
{
	if (m_isWhite->GetCheck())
	{
		m_isBlack->SetCheck(FALSE);
	}
	else
	{
		m_isBlack->SetCheck(TRUE);
	}
}

//设置黑白名单
void CdllMFCDlg::OnBnClickedButton3()
{
	WCHAR dllName[255] = { 0 };
	GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(L"动态库为空");
		return;
	}

	HMODULE hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(L"动态库加载失败");
		return;
	}

	_SetWorkMode setWorkMode = (_SetWorkMode)GetProcAddress(hModule, "SetWorkMode");
	if (!setWorkMode)
	{
		FreeLibrary(hModule);
		hModule = NULL;
		MessageBox(L"动态库获取函数失败失败");
		return;
	}

	WorkMode_EM workMode = BLACK;
	if (m_isWhite->GetCheck())
	{
		workMode = WHITE;
	}

	ULONG ret = setWorkMode(workMode);
	if (ret != SUCCESS)
	{
		FreeLibrary(hModule);
		hModule = NULL;

		DWORD error = GetLastError();
		WCHAR tmp[24] = { 0 };
		wsprintf(tmp, L"设置黑白名单失败:%s(%d)", GetErrorString(ret),error);

		MessageBox(tmp);

		return;
	}

	FreeLibrary(hModule);
	hModule = NULL;

	MessageBox(L"设置黑白名单成功");
}

//开启自动采集
void CdllMFCDlg::OnBnClickedCheck46()
{
	BOOL isCollectCheck = m_autoCollectCheck->GetCheck();

	m_autoCollectBt->EnableWindow(isCollectCheck);
	m_stopAutoCollectBt->EnableWindow(isCollectCheck);

	m_getDataBt->EnableWindow(!isCollectCheck);
}

DWORD WINAPI AutoCollectThread(LPVOID param)
{
	CdllMFCDlg* mfcdlg = (CdllMFCDlg*)param;

	WCHAR dllName[255] = { 0 };
	mfcdlg->GetDlgItemText(IDC_EDIT1, dllName, 254);
	if (dllName[0] == L'\0')
	{
		MessageBox(NULL,L"动态库为空",0,0);
		mfcdlg->m_autoCollectBt->EnableWindow(TRUE);
		return 0;
	}

	HMODULE hModule = LoadLibrary(dllName);
	if (NULL == hModule)
	{
		MessageBox(NULL,L"动态库加载失败",0,0);
		mfcdlg->m_autoCollectBt->EnableWindow(TRUE);
		return 0;
	}

	g_isAutoCollect = TRUE;
	MessageBox(NULL,L"开始自动采集成功",0,0);
	
	time_t beginTm = time(0);
	while (g_isAutoCollect)
	{
		if (time(0) - beginTm >= mfcdlg->m_collectTime)
		{
			mfcdlg->GetDriverData(hModule);
			beginTm = time(0);
		}
		
		Sleep(1000);
	}

	mfcdlg->m_autoCollectBt->EnableWindow(TRUE);
FINAL:
	if (hModule)
	{
		FreeLibrary(hModule);
		hModule = NULL;
	}

	return 0;
}

//自动采集
void CdllMFCDlg::OnBnClickedButton9()
{
	m_autoCollectBt->EnableWindow(FALSE);

	m_collectTime = 1;

	//WCHAR wCollectTime[255] = { 0 };
	//GetDlgItemText(IDC_EDIT6, wCollectTime, 254);
	//if (wCollectTime[0] == '\0')
	//{
	//	MessageBox(L"自动采集间隔为空，默认1分钟");
	//}
	//else
	//{
	//	m_collectTime = _wtoi(wCollectTime);
	//}

	HANDLE hThread = CreateThread(NULL, 0, AutoCollectThread, this, 0, 0);
	if (!hThread)
	{
		MessageBox(L"创建系统采集线程失败");
		m_autoCollectBt->EnableWindow(TRUE);
		return;
	}

	CloseHandle(hThread);
	hThread = NULL;
}


void CdllMFCDlg::OnBnClickedButton11()
{
	g_isAutoCollect = FALSE;

	MessageBox(L"停止自动采集成功");
	//m_autoCollectBt->EnableWindow(TRUE);
}

