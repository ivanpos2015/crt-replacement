#pragma once

//used for limiting the amount of time that can be consumed

class TimeLimiter {
public:
	TimeLimiter(ULONGLONG ullMaxConsumptionTime = NULL) { this->ullTime = ullMaxConsumptionTime; bEnable = ullMaxConsumptionTime != NULL; };
	TimeLimiter(const TimeLimiter& other) { this->operator=(other); };
	void operator=(const TimeLimiter& other) {
		this->ullTime = other.ullTime; 
		this->bEnable = other.bEnable;
	};
	bool consume(ULONGLONG ullSlice){
		if (!bEnable)
			return true;
		if (ullSlice > ullTime) {
			ullTime = NULL;
			return false;
		}
		ullTime -= ullSlice;
		return (ullTime > 0);
	};
	ULONGLONG time_left() const { return ullTime; };
	void disable() { bEnable = false; };
	void enable() { bEnable = true; };
private:
	bool bEnable;
	ULONGLONG ullTime;
};