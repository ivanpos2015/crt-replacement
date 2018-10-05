#pragma once

namespace Pipe {
	struct sPipeServerHandle {
		SmartPtr<OVERLAPPED> ovl;
		HANDLE pipe;
	};

	class Client {
	public:
		Client(Client&& other) {
			this->bConnected = other.bConnected;
			this->hPipe = other.hPipe;
			this->s_ovl = std::move(other.s_ovl);
			other.hPipe = INVALID_HANDLE_VALUE;
			other.bConnected = false;
		};
		Client(HANDLE hPipe = INVALID_HANDLE_VALUE);
		Client(sPipeServerHandle&& handle);
		bool Connect(AsciiString pipe);
		bool wait(AsciiString pipe, DWORD dwTimeOut = 10000);
		template <typename T>
		T read(bool* bRead = nullptr);
		template <typename T>
		bool write(const T& data);
		bool read(LPVOID pBuffer, DWORD len);
		bool write(LPCVOID pBuffer, DWORD len);
		bool IsConnected() { return bConnected && hPipe != INVALID_HANDLE_VALUE; };
		~Client();
	private:
		HANDLE hPipe;
		SmartPtr<OVERLAPPED> s_ovl;
		bool bConnected;
	};

	class Server {
	public:
		Server(AsciiString name);
		~Server();
		sPipeServerHandle accept();
		bool isAvailable();
	private:
		HANDLE listen();
		SECURITY_ATTRIBUTES sec;
		AsciiString server;
		HANDLE hPipe;
	};
};

template<typename T>
inline T Pipe::Client::read(bool * bRead)
{
	if (bRead != nullptr)
		*bRead = false;
	T tmp;
	DWORD dwRead;
	BOOL bSuccessfullyRead = ::ReadFile(hPipe, &tmp, sizeof(T), &dwRead, nullptr);
	if (!bSuccessfullyRead || dwRead != sizeof(T))
		return false;
	if (bRead != nullptr)
		*bRead = true;
	return tmp;
}

template<typename T>
inline bool Pipe::Client::write(const T& data)
{
	DWORD dwWritten;
	BOOL bWritten = ::WriteFile(hPipe, &data, sizeof(T), &dwWritten, nullptr);
	return bWritten && dwWritten == sizeof(T);
}