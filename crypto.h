#pragma once

namespace Crypto {

	//https://msdn.microsoft.com/en-us/library/windows/desktop/aa379941(v=vs.85).aspx
	/*
	The key size, representing the length of the key modulus in bits,
	is set with the upper 16 bits of this parameter.
	Thus, if a 2,048-bit RSA signature key is to be generated,
	the value 0x08000000 is combined with any other dwFlags predefined value with a bitwise-OR operation.
	The upper 16 bits of 0x08000000 is 0x0800, or decimal 2,048.

	1024 << 16 = 0x04000000
	2048 << 16 = 0x08000000
	4096 << 16 = 0x10000000
	8192 << 16 = 0x20000000
	16384 << 16 = 0x40000000
	*/

#define RSA1024BIT_KEY  0x04000000
#define RSA2048BIT_KEY  0x08000000
#define RSA4096BIT_KEY  0x10000000
#define RSA8192BIT_KEY  0x20000000
#define RSA16384BIT_KEY 0x40000000


	class Session {
	public:
		enum CryptoFlags {
			cf_none,
			cf_server,
			cf_client
		};

		Session(CryptoFlags flags = cf_none, DWORD dwKeyType = RSA2048BIT_KEY);
		~Session();
		void operator=(Session&& other) {
			//Session::~Session(); //or: this->~Session(); //WARNING: DON'T USE, WILL DESTRUCT THE INSTANCE!!!
			if (hSessionKey_AES)
				CryptDestroyKey(hSessionKey_AES);
			if (hSessionKey_RSA)
				CryptDestroyKey(hSessionKey_RSA);
			if (hProv)
				CryptReleaseContext(hProv, 0);
			this->hProv = other.hProv;
			this->bSessionKeyImported = other.bSessionKeyImported;
			this->hSessionKey_AES = other.hSessionKey_AES;
			this->hSessionKey_RSA = other.hSessionKey_RSA;
			other.hProv = NULL;
			other.bSessionKeyImported = false;
			other.hSessionKey_AES = other.hSessionKey_RSA = NULL;
		};

		bool ExportRSAPublicKey(PCRYPT_DATA_BLOB key);
		bool ImportRSAPublicKey(PCRYPT_DATA_BLOB key);
		bool ExportSymmetricKey(PCRYPT_DATA_BLOB key);
		bool ImportSymmetricKey(PCRYPT_DATA_BLOB key);

		DWORD AcquireEncryptedLength(DWORD dwDataLen);
		bool encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen);
		bool decrypt(PBYTE pData, PDWORD lpdwDataLen);
		bool enabled() { return bSessionKeyImported; };
		bool usable() { return hProv != NULL; };
		DWORD RSAKeySize() { return dwRSAKeySize / 8; };
	private:
		DWORD dwRSAKeySize;
		bool bSessionKeyImported;
		HCRYPTPROV hProv;
		HCRYPTKEY hSessionKey_AES, hSessionKey_RSA;
	};

	class AES256 {
	public:
		AES256(LPCSTR password);
		AES256(LPCWSTR password);
		AES256(PBYTE pKey, DWORD dwKeyLen);
		~AES256();
		CRYPT_DATA_BLOB encrypt(PBYTE pData, DWORD dwLen);
		bool decrypt(PBYTE pData, PDWORD dwLen);
		HCRYPTKEY get() { return hCryptKey; };
		DWORD GetEncryptedLen(DWORD dwClearTextLen)
		{
			return (dwClearTextLen / 16 + 1) * 16;
		};
	private:
		DWORD dwBlockSize;
		HCRYPTPROV hCryptProv;
		HCRYPTKEY hCryptKey;
	};

	class RSA {
	public:
		enum KeyTypes {
			RSA_1024BIT_KEY,
			RSA_2048BIT_KEY,
			RSA_4096BIT_KEY,
			RSA_8192BIT_KEY,
			RSA_16384BIT_KEY
		};
		RSA();
		~RSA();
		bool generate_key(ALG_ID AlgId = AT_SIGNATURE, KeyTypes type = RSA_2048BIT_KEY);
		bool export_private_key(PCHAR password, PCRYPT_DATA_BLOB data);
		bool export_public_key(PCRYPT_DATA_BLOB data);
		bool import_private_key(PCHAR password, PCRYPT_DATA_BLOB data);
		bool import_public_key(PCRYPT_DATA_BLOB data);
		HCRYPTKEY key() { return hCryptKey; };
		HCRYPTPROV prov() { return hCryptProv; };
		size_t size() { return _size; };
		bool encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen);
		bool decrypt(PBYTE pData, PDWORD lpdwDataLen);
	private:
		size_t _size;
		HCRYPTKEY hCryptKey;
		HCRYPTPROV hCryptProv;
	};

	class Sign {
	public:
		Sign(RSA& rsa) :rsa(rsa) {};
		bool SignData(PBYTE pData, DWORD dwDataLen, PBYTE* pSignature, PDWORD pdwSignatureLen);
		CRYPT_DATA_BLOB sign(PCRYPT_DATA_BLOB data);
		bool verify(PCRYPT_DATA_BLOB data, PCRYPT_DATA_BLOB signature);
	private:
		RSA& rsa;
	};

	
#define SHA512_LEN 64
	struct SHA512Hash {
		BYTE result[SHA512_LEN];
	};


	class SHA512 {
	public:
		SHA512();
		~SHA512();
		bool HashData(SHA512Hash& hash, CRYPT_DATA_BLOB data);
	private:
		HCRYPTPROV hCryptProv;
	};
	
	#define SHA256_LEN 32

struct SHA256Hash {
	BYTE result[SHA256_LEN];
};

class SHA256 {
public:
	SHA256();
	~SHA256();
	bool HashData(SHA256Hash& hash, CRYPT_DATA_BLOB data);
private:
	HCRYPTPROV hCryptProv;
};


	class GenRandom {
	public:
		GenRandom();
		~GenRandom();
		bool Generate(PBYTE pData, DWORD dwLen);
	private:
		HCRYPTPROV hCryptProv;
	};

};