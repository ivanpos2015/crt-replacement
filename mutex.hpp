#pragma once

class Mutex {
public:
	Mutex()
	{
		InitializeCriticalSection(&cs);
	};

	~Mutex()
	{
		DeleteCriticalSection(&cs);
	};

	void lock() const
	{
		EnterCriticalSection(&cs);
	};

	bool try_lock() const
	{
		return TryEnterCriticalSection(&cs) == TRUE;
	};

	void unlock() const
	{
		LeaveCriticalSection(&cs);
	};
private:
	mutable CRITICAL_SECTION cs;
};

class MutexLocker {
public:
	MutexLocker(const Mutex& m, bool bLock = true):mutex(m)
	{
		if (bLock)
			mutex.lock();
		bIsLocked = bLock;
	};
	~MutexLocker()
	{
		if (bIsLocked)
			mutex.unlock();
	};

	MutexLocker(const MutexLocker& m, bool bRelock = true) :mutex(m.mutex)
	{
		if (bRelock)
			mutex.lock();
		bIsLocked = bRelock;
	};

	MutexLocker(MutexLocker&& m) :mutex(m.mutex), bIsLocked(m.bIsLocked)
	{
		m.bIsLocked = false;
	};
	
	void relock() const
	{
		if (bIsLocked)
			return;
		bIsLocked = false;
		mutex.lock();
	};

	void unlock() const
	{
		if (bIsLocked)
			mutex.unlock();
		bIsLocked = false;
	};
private:
	const Mutex& mutex;
	mutable bool bIsLocked;
};

template <typename T>
class SpinLock {
public:
	SpinLock(T* value) {
		p = value;
		if (!value)
			return;
		bIsLocked = false;
		relock();
	};
	void relock() {
		if (bIsLocked || !p)
			return;
		while (InterlockedCompareExchange(p, 1, 0) != 0)
			Sleep(1);
		bIsLocked = true;
	};
	void unlock() {
		if (p && bIsLocked)
			InterlockedExchange(p, NULL);
		bIsLocked = false;
	};
	~SpinLock() { unlock(); };
private:
	bool bIsLocked;
	T* p;
};