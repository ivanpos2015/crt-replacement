#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifdef NO_CRT
#ifndef _WIN64
//so 32-bit crt doesn't conflict.
#define __STDC_WANT_SECURE_LIB__ 0
#define _CRT_SECURE_NO_WARNINGS
#define __STRALIGN_H_
#define _SYS_GUID_OPERATORS_
#define _INC_STRING
#define __STDC__ 1
#else
//so 64-bit crt doesn't conflict.
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#define __STRALIGN_H_
#define _SYS_GUID_OPERATORS_
#define _INC_STRING
#define __STDC__ 1
#define __STDC_WANT_SECURE_LIB__ 0
#define _STRALIGN_USE_SECURE_CRT 0
#endif
#endif
#include <Windows.h>
#include <wincrypt.h>
#ifdef NO_CRT
#include "utils/crt.h"
#else
#include <iostream>
#endif
#include "crypto.h"

#pragma comment(lib, "Crypt32.lib")

namespace Crypto {

	//------------------------------------------------
	Session::Session(CryptoFlags flags, DWORD dwKeyType)
	{
		dwRSAKeySize = (dwKeyType >> 16);
		bSessionKeyImported = false;
		hProv = NULL;
		hSessionKey_AES = NULL;
		hSessionKey_RSA = NULL;
		if (flags == cf_none)
			return;
		if (!CryptAcquireContext(&hProv, nullptr, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) && GetLastError() == NTE_BAD_KEYSET)
			if (!CryptAcquireContext(&hProv, nullptr, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
				return;
		if (flags == cf_server) {
			if (!CryptGenKey(hProv, AT_KEYEXCHANGE, dwKeyType | CRYPT_EXPORTABLE, &hSessionKey_RSA))
				return;
		}
		else if (flags == cf_client) {
			if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hSessionKey_AES))
				return;
			bSessionKeyImported = true;
		}
	}

	bool Session::ExportRSAPublicKey(PCRYPT_DATA_BLOB key)
	{
		ZeroMemory(key, sizeof(CRYPT_DATA_BLOB));
		if (!hSessionKey_RSA)
			return false;
		DWORD dwBlobLen = NULL;
		if (::CryptExportKey(hSessionKey_RSA, NULL, PUBLICKEYBLOB, 0, nullptr, &dwBlobLen)) {
			PBYTE pBlob = new BYTE[dwBlobLen];
			if (::CryptExportKey(hSessionKey_RSA, NULL, PUBLICKEYBLOB, 0, pBlob, &dwBlobLen)) {
				key->pbData = pBlob;
				key->cbData = dwBlobLen;
				return true;
			}
			else
				delete[] pBlob;
		}
		return false;
	}

	bool Session::ImportRSAPublicKey(PCRYPT_DATA_BLOB key)
	{
		return (::CryptImportKey(hProv, key->pbData, key->cbData, 0, 0, &hSessionKey_RSA) == TRUE);
	}

	bool Session::ExportSymmetricKey(PCRYPT_DATA_BLOB key)
	{
		ZeroMemory(key, sizeof(CRYPT_DATA_BLOB));
		if (!hSessionKey_AES || !hSessionKey_RSA)
			return false;
		DWORD dwBlobLen = NULL;
		if (::CryptExportKey(hSessionKey_AES, hSessionKey_RSA, SIMPLEBLOB, 0, nullptr, &dwBlobLen)) {
			PBYTE pBlob = new BYTE[dwBlobLen];
			if (::CryptExportKey(hSessionKey_AES, hSessionKey_RSA, SIMPLEBLOB, 0, pBlob, &dwBlobLen)) {
				key->pbData = pBlob;
				key->cbData = dwBlobLen;
				return true;
			}
			else
				delete[] pBlob;
		}
		return false;
	}

	bool Session::ImportSymmetricKey(PCRYPT_DATA_BLOB key)
	{
		return (bSessionKeyImported = (::CryptImportKey(hProv, key->pbData, key->cbData, hSessionKey_RSA, 0, &hSessionKey_AES) == TRUE));
	}

	DWORD Session::AcquireEncryptedLength(DWORD dwDataLen)
	{
		if (!bSessionKeyImported)
			return NULL;
		/*
		DWORD dwTmp = dwDecryptedLen;
		DWORD dwLen = sizeof(DWORD);

		BOOL bAcquired = CryptEncrypt(hSessionKey_AES, NULL, TRUE, 0, nullptr, &dwTmp, 0);
		if (!bAcquired)
		return NULL;
		return dwTmp;
		*/
		DWORD dwBlockLen = NULL, dwLen = sizeof(dwBlockLen);
		if (!CryptGetKeyParam(hSessionKey_AES, KP_BLOCKLEN, (PBYTE)&dwBlockLen, &dwLen, 0) || dwBlockLen == NULL)
			return NULL;
		dwBlockLen /= 8;
		return (dwDataLen / dwBlockLen + 1) * dwBlockLen;
	}

	bool Session::encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen)
	{
		if (!bSessionKeyImported)
			return false;
		return (CryptEncrypt(hSessionKey_AES, NULL, TRUE, 0, pData, lpdwDataLen, dwBufferLen) == TRUE);
	}

	bool Session::decrypt(PBYTE pData, PDWORD lpdwDataLen)
	{
		if (!bSessionKeyImported)
			return false;
		return (CryptDecrypt(hSessionKey_AES, NULL, TRUE, 0, pData, lpdwDataLen) == TRUE);
	}

	Session::~Session()
	{
		if (hSessionKey_AES)
			CryptDestroyKey(hSessionKey_AES);
		if (hSessionKey_RSA)
			CryptDestroyKey(hSessionKey_RSA);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	//------------------------------------------------

	AES256::AES256(LPCSTR password) :AES256((PBYTE)password, strlen(password))
	{

	}

	AES256::AES256(LPCWSTR password) : AES256((PBYTE)password, wcslen(password) * sizeof(wchar_t))
	{

	}

	AES256::AES256(PBYTE pKey, DWORD dwKeyLen)
	{
		dwBlockSize = NULL;
		hCryptKey = NULL;
		if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			return;
		HCRYPTHASH hHash;
		if (!CryptCreateHash(hCryptProv, CALG_SHA_512, NULL, NULL, &hHash))
			return;
		if (!CryptHashData(hHash, pKey, dwKeyLen, 0)) {
			CryptDestroyHash(hHash);
			return;
		}
		if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, NULL, &hCryptKey)) {
			hCryptKey = NULL;
		}
		else {
			DWORD dwBlockLen = NULL, dwLen = sizeof(dwBlockLen);
			if (CryptGetKeyParam(hCryptKey, KP_BLOCKLEN, (PBYTE)&dwBlockLen, &dwLen, 0) || dwBlockLen == NULL) {
				dwBlockLen /= 8;
				dwBlockSize = dwBlockLen;
			}
			else
				dwBlockSize = 16;
		}
		CryptDestroyHash(hHash);
	}

	CRYPT_DATA_BLOB AES256::encrypt(PBYTE pData, DWORD dwLen)
	{
		if (!hCryptKey || !pData || !dwLen)
			return{ 0 };
		DWORD dwChunkSize = 1024 - (1024 % dwBlockSize);
		DWORD nBlocks = (dwLen / dwChunkSize) + ((dwLen % dwChunkSize) ? 1 : 0);
		BOOL bFinal = FALSE;
		CRYPT_DATA_BLOB encrypted = { 0 };
		encrypted.cbData = ((dwLen / dwBlockSize) + 1) * dwBlockSize;
		encrypted.pbData = new BYTE[encrypted.cbData];
		memcpy(encrypted.pbData, pData, dwLen);
		for (DWORD i = 0; i < nBlocks; i++) {
			if (i + 1 == nBlocks)
				bFinal = TRUE;
			DWORD dwDataLen = bFinal ? (dwLen - (dwChunkSize * i)) : dwChunkSize;
			if (!CryptEncrypt(hCryptKey, NULL, bFinal, 0, &encrypted.pbData[i * dwChunkSize], &dwDataLen, encrypted.cbData - (i * dwChunkSize))) {
				delete encrypted.pbData;
				return{ 0 };
			}
		}
		return encrypted;
	}

	bool AES256::decrypt(PBYTE pData, PDWORD dwLen)
	{
		if (!hCryptKey || !pData || !dwLen)
			return false;
		DWORD dwChunkSize = 1024 - (1024 % dwBlockSize);
		DWORD nBlocks = (*dwLen / dwChunkSize) + ((*dwLen % dwChunkSize) ? 1 : 0);
		BOOL bFinal = FALSE;
		DWORD dwLenTmp = NULL;
		for (DWORD i = 0; i < nBlocks; i++) {
			if (i + 1 == nBlocks)
				bFinal = TRUE;
			DWORD dwDataLen = bFinal ? (*dwLen - (i * dwChunkSize)) : dwChunkSize;
			if (!CryptDecrypt(hCryptKey, NULL, bFinal, 0, &pData[i * dwChunkSize], &dwDataLen)) {
				*dwLen = NULL;
				return false;
			}
			dwLenTmp += dwDataLen; //dwDataLen now contains the decrypted chunk size
		}
		*dwLen = dwLenTmp;
		return true;
	}

	AES256::~AES256()
	{
		if (hCryptKey)
			CryptDestroyKey(hCryptKey);
		if (hCryptProv)
			CryptReleaseContext(hCryptProv, 0);
	}

	RSA::RSA()
	{
		_size = NULL;
		hCryptKey = NULL;
		hCryptProv = NULL;
		CryptAcquireContext(&hCryptProv, L"crypto_container", nullptr, PROV_RSA_AES, CRYPT_DELETEKEYSET);
		if (!CryptAcquireContext(&hCryptProv, L"crypto_container", nullptr, PROV_RSA_AES, NULL)) {
			if (GetLastError() == NTE_BAD_KEYSET)
			{
				if (!CryptAcquireContext(&hCryptProv, L"crypto_container", nullptr, PROV_RSA_AES, CRYPT_NEWKEYSET))
					hCryptProv = NULL;
			}
		}
	}

	DWORD GetKeyType(RSA::KeyTypes type)
	{
		switch (type) {
		case RSA::KeyTypes::RSA_1024BIT_KEY:
			return RSA1024BIT_KEY;
			break;
		case RSA::KeyTypes::RSA_2048BIT_KEY:
			return RSA2048BIT_KEY;
			break;
		case RSA::KeyTypes::RSA_4096BIT_KEY:
			return RSA4096BIT_KEY;
			break;
		case RSA::KeyTypes::RSA_8192BIT_KEY:
			return RSA8192BIT_KEY;
			break;
		case RSA::KeyTypes::RSA_16384BIT_KEY:
			return RSA16384BIT_KEY;
			break;
		default:
			return RSA2048BIT_KEY;
		}
	}

	size_t DetermineRSASize(RSA::KeyTypes type)
	{
		switch (type) {
		case RSA::KeyTypes::RSA_1024BIT_KEY:
			return 128;
			break;
		case RSA::KeyTypes::RSA_2048BIT_KEY:
			return 256;
			break;
		case RSA::KeyTypes::RSA_4096BIT_KEY:
			return 512;
			break;
		case RSA::KeyTypes::RSA_8192BIT_KEY:
			return 1024;
			break;
		case RSA::KeyTypes::RSA_16384BIT_KEY:
			return 2048;
			break;
		default:
			return 256;
		}
	}

	bool RSA::generate_key(ALG_ID AlgId, KeyTypes type)
	{
		if (!hCryptProv)
			return false;
		//CryptAcquireCertificatePrivateKey
		//note: with AT_SIGNATURE you can only sign & verify data.
		//But with AT_KEYEXCHANGE you can only decrypt/encrypt data(you can't use it for signing data).
		if (CryptGenKey(hCryptProv, AlgId, GetKeyType(type) | CRYPT_EXPORTABLE, &hCryptKey)) {
			_size = DetermineRSASize(type);
			return true;
		}
		return false;
	}

	bool RSA::import_private_key(PCHAR password, PCRYPT_DATA_BLOB data)
	{
		if (!hCryptProv)
			return false;
		AES256 key(password);
		if (!key.decrypt(data->pbData, &data->cbData))
			return false;
		return CryptImportKey(hCryptProv, data->pbData, data->cbData, NULL, 0, &hCryptKey) == TRUE;
		//return CryptImportKey(hCryptProv, data->pbData, data->cbData, key.get(), 0, &hCryptKey) == TRUE;
	}

	bool RSA::import_public_key(PCRYPT_DATA_BLOB data)
	{
		if (!hCryptProv)
			return false;
		_size = data->cbData - 20;
		return CryptImportKey(hCryptProv, data->pbData, data->cbData, NULL, 0, &hCryptKey) == TRUE;
	}

	bool RSA::export_private_key(PCHAR password, PCRYPT_DATA_BLOB data)
	{
		data->cbData = NULL;
		data->pbData = nullptr;
		if (!hCryptProv)
			return false;
		AES256 key(password);
		if (CryptExportKey(
			hCryptKey,
			NULL,
			PRIVATEKEYBLOB,
			0,
			nullptr,
			&data->cbData))
		{
			data->pbData = new BYTE[data->cbData];
			if (CryptExportKey(
				hCryptKey,
				NULL,
				PRIVATEKEYBLOB,
				0,
				data->pbData,
				&data->cbData))
			{
				CRYPT_DATA_BLOB enc = key.encrypt(data->pbData, data->cbData);
				delete data->pbData;
				data->pbData = enc.pbData;
				data->cbData = enc.cbData;
				return true;
			}
		}
		return false;
	}

	bool RSA::export_public_key(PCRYPT_DATA_BLOB data)
	{
		if (!hCryptProv)
			return false;
		if (CryptExportKey(
			hCryptKey,
			NULL,
			PUBLICKEYBLOB,
			0,
			nullptr,
			&data->cbData))
		{
			data->pbData = new BYTE[data->cbData];
			if (CryptExportKey(
				hCryptKey,
				NULL,
				PUBLICKEYBLOB,
				0,
				data->pbData,
				&data->cbData))
			{
				return true;
			}
		}
		return false;
	}

	bool RSA::encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen)
	{
		if (hCryptKey == NULL)
			return false;
		return (CryptEncrypt(hCryptKey, NULL, TRUE, 0, pData, lpdwDataLen, dwBufferLen) == TRUE);
	}

	bool RSA::decrypt(PBYTE pData, PDWORD lpdwDataLen)
	{
		if (hCryptKey == NULL)
			return false;
		return (CryptDecrypt(hCryptKey, NULL, TRUE, 0, pData, lpdwDataLen) == TRUE);
	}

	RSA::~RSA()
	{
		if (hCryptKey)
			CryptDestroyKey(hCryptKey);
		if (hCryptProv)
			CryptReleaseContext(hCryptProv, 0);
	}
	bool Sign::SignData(PBYTE pData, DWORD dwDataLen, PBYTE* pSignature, PDWORD pdwSignatureLen)
	{
		if (pSignature) {
			*pSignature = nullptr;
			*pdwSignatureLen = NULL;
		}
		if (!pSignature || !pData || !dwDataLen)
			return false;
		if (rsa.key() == NULL)
			return false;
		HCRYPTHASH hHash = NULL;
		if (!CryptCreateHash(rsa.prov(), CALG_SHA_512, 0, 0, &hHash))
			return false;
		if (!CryptHashData(hHash, pData, dwDataLen, NULL)) {
			CryptDestroyHash(hHash);
			return false;
		}
		bool bResult = false;
		if (CryptSignHash(hHash, AT_SIGNATURE, nullptr, 0, nullptr, pdwSignatureLen))
		{
			*pSignature = new BYTE[*pdwSignatureLen];
			if (CryptSignHash(hHash, AT_SIGNATURE, nullptr, 0, *pSignature, pdwSignatureLen))
			{
				bResult = true;
			}
		}
		CryptDestroyHash(hHash);
		return bResult;
	}

	CRYPT_DATA_BLOB Crypto::Sign::sign(PCRYPT_DATA_BLOB data)
	{
		CRYPT_DATA_BLOB signature = { 0 };
		//signature size should be 256 bytes
		if (data == nullptr)
			return signature;
		this->SignData(data->pbData, data->cbData, &signature.pbData, &signature.cbData);
		return signature;
	}

	bool Crypto::Sign::verify(PCRYPT_DATA_BLOB data, PCRYPT_DATA_BLOB signature)
	{
		if (!signature || !data || data->pbData == nullptr || signature->pbData == nullptr)
			return false;
		if (rsa.key() == NULL)
			return false;
		HCRYPTHASH hHash = NULL;
		if (!CryptCreateHash(rsa.prov(), CALG_SHA_512, 0, 0, &hHash))
			return false;
		if (!CryptHashData(hHash, data->pbData, data->cbData, NULL)) {
			CryptDestroyHash(hHash);
			return false;
		}
		return CryptVerifySignature(hHash, signature->pbData, signature->cbData, rsa.key(), nullptr, 0) == TRUE;
	}

	SHA512::SHA512()
	{
		hCryptProv = NULL;
		if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, NULL)) {
			if (GetLastError() == NTE_BAD_KEYSET)
			{
				if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_NEWKEYSET))
					hCryptProv = NULL;
			}
			else
				hCryptProv = NULL;
		}
	}

	SHA512::~SHA512()
	{
		if (hCryptProv)
			CryptReleaseContext(hCryptProv, NULL);
	}

	bool SHA512::HashData(SHA512Hash & hash, CRYPT_DATA_BLOB data)
	{
		ZeroMemory(&hash.result[0], sizeof(hash.result));
		if (hCryptProv == NULL)
			return false;
		HCRYPTHASH hHash = NULL;
		if (!CryptCreateHash(hCryptProv, CALG_SHA_512, 0, 0, &hHash))
			return false;
		if (!CryptHashData(hHash, data.pbData, data.cbData, NULL)) {
			CryptDestroyHash(hHash);
			return false;
		}
		DWORD dwHashLen, dwHashLenSize = sizeof(dwHashLen);
		if (!CryptGetHashParam(
			hHash,
			HP_HASHSIZE,
			(BYTE *)&dwHashLen,
			&dwHashLenSize,
			0))
		{
			CryptDestroyHash(hHash);
			return false;
		}
		if (dwHashLen != SHA512_LEN)
			return false;
		bool bSuccess = false;
		if (CryptGetHashParam(hHash, HP_HASHVAL, &hash.result[0], &dwHashLen, 0))
			bSuccess = true;
		CryptDestroyHash(hHash);
		return bSuccess;
	}
	
	
	// ------------------- sha256 ----------------------
	
	SHA256::SHA256()
{
	hCryptProv = NULL;
	if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, NULL)) {
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_NEWKEYSET))
				hCryptProv = NULL;
		}
		else
			hCryptProv = NULL;
	}
}

SHA256::~SHA256()
{
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, NULL);
}

bool SHA256::HashData(SHA256Hash & hash, CRYPT_DATA_BLOB data)
{
	ZeroMemory(&hash.result[0], sizeof(hash.result));
	if (hCryptProv == NULL)
		return false;
	HCRYPTHASH hHash = NULL;
	if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
		return false;
	if (!CryptHashData(hHash, data.pbData, data.cbData, NULL)) {
		CryptDestroyHash(hHash);
		return false;
	}
	DWORD dwHashLen, dwHashLenSize = sizeof(dwHashLen);
	if (!CryptGetHashParam(
		hHash,
		HP_HASHSIZE,
		(BYTE *)&dwHashLen,
		&dwHashLenSize,
		0))
	{
		CryptDestroyHash(hHash);
		return false;
	}
	if (dwHashLen != SHA256_LEN)
		return false;
	bool bSuccess = false;
	if (CryptGetHashParam(hHash, HP_HASHVAL, &hash.result[0], &dwHashLen, 0))
		bSuccess = true;
	CryptDestroyHash(hHash);
	return bSuccess;
}

	


	GenRandom::GenRandom()
	{
		hCryptProv = NULL;
		if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, NULL)) {
			if (GetLastError() == NTE_BAD_KEYSET)
			{
				if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_NEWKEYSET))
					hCryptProv = NULL;
			}
			else
				hCryptProv = NULL;
		}
	}

	bool Crypto::GenRandom::Generate(PBYTE pData, DWORD dwLen)
	{
		if (hCryptProv == NULL)
			return false;
		SecureZeroMemory(pData, dwLen);
		return ::CryptGenRandom(hCryptProv, dwLen, pData) == TRUE;
	}

	GenRandom::~GenRandom()
	{
		if (hCryptProv)
			CryptReleaseContext(hCryptProv, NULL);
	}

};
