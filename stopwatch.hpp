#pragma once

class StopWatch {
public:
	StopWatch() { reset(); };
	StopWatch(StopWatch&& other) { this->operator=(other); other.ullTick = NULL; };
	void operator=(const StopWatch& other) { ullTick = other.ullTick; };
	ULONGLONG elapsed() { return GetTickCount64() - InterlockedExchangeAdd(&ullTick, NULL); };
	void reset() { InterlockedExchange(&ullTick, GetTickCount64()); };
private:
	ULONGLONG ullTick;
};

class StopWatch2 {
public:
	StopWatch2() { ullStart = ullEnd = NULL; };
	StopWatch2(const StopWatch2& other) { ullStart = other.ullStart; ullEnd = other.ullEnd; };
	void operator=(const StopWatch2& other) { this->StopWatch2::StopWatch2(other); };
	void start() { ullStart = GetTickCount64(); };
	void stop() { ullEnd = GetTickCount64(); };
	ULONGLONG elapsed() { return ullEnd - ullStart; };
private:
	ULONGLONG ullStart, ullEnd;
};