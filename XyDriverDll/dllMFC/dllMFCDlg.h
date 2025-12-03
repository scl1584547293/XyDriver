
// dllMFCDlg.h : 头文件
//

#pragma once
#include "MyEdit.h"
#include "afxwin.h"
#include "publicfun.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif

void Writelog(std::string strOutData);

// CdllMFCDlg 对话框
class CdllMFCDlg : public CDialogEx
{
// 构造
public:
	CdllMFCDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLLMFC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CMyEdit m_myEdit;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton7();
	CMyEdit m_driverEdit;
	afx_msg void OnBnClickedButton10();

	//获取数据
	ULONG GetDriverData(HMODULE hModule);

	CMyEdit m_ConfigEdit;

	BOOL GetFileData(LPWCH filePath,PVOID& fileData,PDWORD pFileSize);
	afx_msg void OnBnClickedButton13();

//======================策略配置 begin=====================================================
	afx_msg VOID InitComboBox();

	CComboBox* m_policyComboBox;
	CComboBox* m_policyOperationComboBox;

//==========================end============================================================

//======================开关配置 begin=====================================================

	VOID GetConfigData(PVOID pConfigs);

	//初始化开关
	afx_msg VOID InitCheckBox();
	afx_msg VOID InitProcessCheckBox();
	afx_msg VOID InitThreadCheckBox();
	afx_msg VOID InitFileCheckBox();
	afx_msg VOID InitRegistryCheckBox();
	afx_msg VOID InitSocketCheckBox();
	afx_msg VOID InitUSBCheckBox();

	afx_msg VOID SetProcessConfigDisable(BOOL isDisable);
	afx_msg VOID SetThreadConfigDisable(BOOL isDisable);
	afx_msg VOID SetFileConfigDisable(BOOL isDisable);
	afx_msg VOID SetRegistryConfigDisable(BOOL isDisable);
	afx_msg VOID SetSocketConfigDisable(BOOL isDisable);
	afx_msg VOID SetUSBConfigDisable(BOOL isDisable);

	afx_msg VOID SetAllCheck(BOOL isDisable);
	afx_msg VOID SetProcessCheck(BOOL isDisable);
	afx_msg VOID SetThreadCheck(BOOL isDisable);
	afx_msg VOID SetFileCheck(BOOL isDisable);
	afx_msg VOID SetRegistryCheck(BOOL isDisable);
	afx_msg VOID SetSocketCheck(BOOL isDisable);
	afx_msg VOID SetUSBCheck(BOOL isDisable);

	CButton* m_allConfigCheck;

	//是否黑名单
	CButton* m_isBlack;
	//是否白名单
	CButton* m_isWhite;

	//进程开关
	CButton* m_processCheck;
	//线程开关
	CButton* m_threadCheck;
	//注册表开关
	CButton* m_registryCheck;
	//文件开关
	CButton* m_fileCheck;
	//网络开关
	CButton* m_socketCheck;
	//热插拔开关
	CButton* m_hotplugCheck;
	//模块加载开关
	CButton* m_loadimageCheck;

	//进程开关（全选）
	CButton* m_processAllCheck;
	//进程创建
	CButton* m_processCreateCheck;
	//进程打开
	CButton* m_processOpenCheck;
	//进程退出
	CButton* m_processExitCheck;
	//进程启动
	CButton* m_processStartCheck;

	//线程开关（全选）
	CButton* m_threadAllCheck;
	//线程创建
	CButton* m_threadCreateCheck;
	//线程打开
	CButton* m_threadOpenCheck;
	//线程退出
	CButton* m_threadExitCheck;
	//线程启动
	CButton* m_threadStartCheck;

	//注册表开关（全选）
	CButton* m_registryAllCheck;
	//注册表创建
	CButton* m_registryCreateCheck;
	//注册表打开
	CButton* m_registryOpenCheck;
	//注册表删除项
	CButton* m_registryDeleteKeyCheck;
	//注册表重命名
	CButton* m_registryRenameCheck;
	//注册表枚举
	CButton* m_registryEnumCheck;
	//注册表删除值
	CButton* m_registryDeleteValueCheck;
	//注册表设置值
	CButton* m_registrySetValueCheck;
	//注册表查询值
	CButton* m_registryQueryValueCheck;

	//文件开关（全选）
	CButton* m_fileAllCheck;
	//文件创建
	CButton* m_fileCreateCheck;
	//文件打开
	CButton* m_fileOpenCheck;
	//文件关闭
	CButton* m_fileCloseCheck;
	//文件读取
	CButton* m_fileReadCheck;
	//文件写入
	CButton* m_fileWriteCheck;
	//文件删除
	CButton* m_fileDeleteCheck;

	//网络开关（全选）
	CButton* m_socketAllCheck;
	//网络创建
	CButton* m_socketCreateCheck;
	//网络绑定端口
	CButton* m_socketBindCheck;
	//网络关闭
	CButton* m_socketCloseCheck;
	//网络连接
	CButton* m_socketConnectCheck;
	//网络发送
	CButton* m_socketSendCheck;
	//网络接收
	CButton* m_socketRevCheck;
	//网络服务端发送
	CButton* m_socketAcceptCheck;

	//USB开关（全选）
	CButton* m_USBAllCheck;
	//USB插入
	CButton* m_USBArrival;
	//USB拔出
	CButton* m_USBRemoval;


	//自动采集开关
	CButton* m_autoCollectCheck;
	//自动采集
	CButton* m_autoCollectBt;
	//关闭自动采集
	CButton* m_stopAutoCollectBt;
	//获取数据
	CButton* m_getDataBt;

	ULONG m_collectTime;

//==========================end============================================================
	afx_msg void OnBnClickedCheck2();
	afx_msg void OnBnClickedCheck3();
	afx_msg void OnBnClickedCheck4();
	afx_msg void OnBnClickedCheck6();
	afx_msg void OnBnClickedCheck5();
	afx_msg void OnBnClickedCheck7();
	afx_msg void OnBnClickedCheck41();
	afx_msg void OnBnClickedCheck42();
	afx_msg void OnBnClickedCheck38();
	afx_msg void OnBnClickedCheck39();
	afx_msg void OnBnClickedCheck40();
	afx_msg void OnBnClickedButton8();
	afx_msg void OnBnClickedCheck1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedCheck47();
	afx_msg void OnBnClickedCheck8();
	afx_msg void OnBnClickedCheck45();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedCheck46();
	afx_msg void OnBnClickedButton9();
	afx_msg void OnBnClickedButton11();
};
