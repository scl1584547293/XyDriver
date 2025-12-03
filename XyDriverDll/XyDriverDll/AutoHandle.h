#pragma once
#include <Windows.h>

class AutoHandle
{
public:
	AutoHandle() throw();
	AutoHandle(AutoHandle& h) throw();
	explicit AutoHandle(HANDLE h) throw();
	~AutoHandle() throw();

	AutoHandle& operator=(AutoHandle& h) throw();

	operator HANDLE() const throw();

	// Attach to an existing handle (takes ownership).
	void Attach(HANDLE h) throw();
	// Detach the handle from the object (releases ownership).
	HANDLE Detach() throw();

	// Close the handle.
	void Close() throw();

public:
	HANDLE m_h;
};

inline AutoHandle::AutoHandle() throw() :
	m_h(INVALID_HANDLE_VALUE)
{
}

inline AutoHandle::AutoHandle(AutoHandle& h) throw() :
	m_h(INVALID_HANDLE_VALUE)
{
	Attach(h.Detach());
}

inline AutoHandle::AutoHandle(HANDLE h) throw() :
	m_h(h)
{
}

inline AutoHandle::~AutoHandle() throw()
{
	if (m_h != INVALID_HANDLE_VALUE)
	{
		Close();
	}
}

inline AutoHandle& AutoHandle::operator=(AutoHandle& h) throw()
{
	if (this != &h)
	{
		if (m_h != INVALID_HANDLE_VALUE)
		{
			Close();
		}
		Attach(h.Detach());
	}

	return(*this);
}

inline AutoHandle::operator HANDLE() const throw()
{
	return(m_h);
}

inline void AutoHandle::Attach(HANDLE h) throw()
{
	m_h = h;  // Take ownership
}

inline HANDLE AutoHandle::Detach() throw()
{
	HANDLE h;

	h = m_h;  // Release ownership
	m_h = INVALID_HANDLE_VALUE;

	return(h);
}

inline void AutoHandle::Close() throw()
{
	if (m_h != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_h);
		m_h = INVALID_HANDLE_VALUE;
	}
}


class AutoEventHandle : public AutoHandle
{
public:
	AutoEventHandle()
	{
		m_h = CreateEvent(NULL, FALSE, FALSE, NULL);
	}
	~AutoEventHandle()
	{
		Close();
	}
};

