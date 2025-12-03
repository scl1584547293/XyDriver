#pragma once
#include "afxwin.h"
class CMyEdit :
	public CEdit
{
public:
	CMyEdit();
	~CMyEdit();
	DECLARE_MESSAGE_MAP()
	afx_msg void OnDropFiles(HDROP hDropInfo);
};

