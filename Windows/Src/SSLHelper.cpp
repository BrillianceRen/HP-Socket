/*
 * Copyright: JessMA Open Source (ldcsaa@gmail.com)
 *
 * Author	: Bruce Liang
 * Website	: http://www.jessma.org
 * Project	: https://github.com/ldcsaa
 * Blog		: http://www.cnblogs.com/ldcsaa
 * Wiki		: http://www.oschina.net/p/hp-socket
 * QQ Group	: 75375912, 44636872
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "stdafx.h"
#include "SSLHelper.h"
#include "SocketHelper.h"

#ifdef _SSL_SUPPORT

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "openssl/x509v3.h"
#include "openssl/md5.h"
#include "../Common/Src/WaitFor.h"


 //add begin 2018-09-03 by renyl, 生成客户端私钥, 证书请求
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <random>
//add end 2018-09-03 by renyl

//add begin 2018-09-10 by renyl, 生成MD5
#include <sstream>
#include <iomanip>
//add end 2018-09-10 by renyl

//add begin 2018-09-15 by renyl, AES-CBC加解密
#include <openssl/aes.h>
//add end 2018-09-15 by renyl

#include <atlpath.h>

/*
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0
	#pragma comment(lib, "libeay32")
	#pragma comment(lib, "ssleay32")
#else
	#pragma comment(lib, "libssl")
	#pragma comment(lib, "libcrypto")
	#pragma comment(lib, "crypt32")
#endif
*/

#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0
int CSSLInitializer::sm_iLockNum = 0;
CSimpleRWLock* CSSLInitializer::sm_pcsLocks = nullptr;
#endif

//add begin 2018-09-03 by renyl, 生成客户端私钥, 证书请求
std::string GetRandString(int len)
{
	try
	{
		string _dic = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`~!@#$%^&*()_+-=[]{}|;:<>?,./";
		random_device rseed;
		mt19937 rgen(rseed()); // mersenne_twister
		uniform_int_distribution<int> idist(0, _dic.length() - 1);
		string dst = "";
		for (int i = 0; i < len; i++)
			dst += _dic.at(idist(rgen));
		return dst;
	}
	catch (...)
	{
		return  std::to_string(time(0));
	}
}

EVP_PKEY* CreateEVP_PKEY(int rsa_key_size)
{
	try
	{
		EVP_PKEY* pkey = nullptr;
		unique_ptr<RSA, decltype(&::RSA_free)> rsakey(RSA_new(), ::RSA_free);
		// Generate the RSA key	
		BIGNUM* bne = BN_new();
		BN_set_word(bne, RSA_F4);
		if (0 == RSA_generate_key_ex(rsakey.get(), rsa_key_size, bne, NULL))
			throw;
		// Create evp obj to hold our rsakey
		pkey = EVP_PKEY_new();
		//EVP_PKEY_assign_RSA(pkey, rsakey.get()); // will be free rsa when EVP_PKEY_free(pkey)
		if (0 == EVP_PKEY_set1_RSA(pkey, rsakey.get()))
			throw;
		return pkey;
	}
	catch (...)
	{
		return nullptr;
	}
}
void ReleaseEVP_PKEY(EVP_PKEY * pkey)
{
	if (pkey != nullptr)
		EVP_PKEY_free(pkey);
}

X509_REQ* CreateX509_REQ(EVP_PKEY* pKey, const CSSLCertHelper::SubjectEntry& subj_entry)
{
	try
	{
		// set version of x509 req
		X509_REQ* x509_req = X509_REQ_new();
		if (1 != X509_REQ_set_version(x509_req, 2))	//2:"version 3"
			throw;

		// set subject of x509 req
		X509_NAME* x509_name = X509_REQ_get_subject_name(x509_req);
		X509_NAME_add_entry_by_txt(x509_name, SN_countryName, MBSTRING_UTF8, (const unsigned char*)subj_entry.country_name.c_str(), -1, -1, 0);	//国家
		X509_NAME_add_entry_by_txt(x509_name, SN_stateOrProvinceName, MBSTRING_UTF8, (const unsigned char*)subj_entry.state_province_name.c_str(), -1, -1, 0);	//省份
		X509_NAME_add_entry_by_txt(x509_name, SN_localityName, MBSTRING_UTF8, (const unsigned char*)subj_entry.locality_name.c_str(), -1, -1, 0);	//地区
		X509_NAME_add_entry_by_txt(x509_name, SN_organizationName, MBSTRING_UTF8, (const unsigned char*)subj_entry.organization_name.c_str(), -1, -1, 0);
		X509_NAME_add_entry_by_txt(x509_name, SN_organizationalUnitName, MBSTRING_UTF8, (const unsigned char*)subj_entry.organizational_unit_name.c_str(), -1, -1, 0);
		X509_NAME_add_entry_by_txt(x509_name, SN_commonName, MBSTRING_UTF8, (const unsigned char*)subj_entry.common_name.c_str(), -1, -1, 0);

		// set public key of x509 req
		if (1 != X509_REQ_set_pubkey(x509_req, pKey))
			throw;

		// set sign key of x509 req
		if (0 >= X509_REQ_sign(x509_req, pKey, EVP_sha1()))    // return x509_req->signature->length
			throw;

		return x509_req;
	}
	catch (...)
	{
		return nullptr;
	}
}
void ReleaseX509_REQ(X509_REQ* req)
{
	if (req != nullptr)
		X509_REQ_free(req);
}

bool EVP_PKEYToPem(EVP_PKEY * pkey, const string& password, std::string & ras_key_pem)
{
	try
	{
		std::unique_ptr<BIO, decltype(&::BIO_free)> bio(BIO_new(BIO_s_mem()), ::BIO_free);
		if (password.empty())
			PEM_write_bio_PrivateKey(bio.get(), pkey, NULL, NULL, 0, 0, NULL);
		else
			PEM_write_bio_PrivateKey(bio.get(), pkey, EVP_aes_256_cbc(), NULL, 0, 0, (void*)password.c_str());
		BUF_MEM *key_buf;
		BIO_get_mem_ptr(bio.get(), &key_buf);
		int key_len = key_buf->length;
		char* private_key = (char*)calloc(1, key_len + 1);
		BIO_read(bio.get(), private_key, key_len);
		ras_key_pem = private_key;
		free(private_key);
		private_key = nullptr;
		return true;
	}
	catch (...)
	{
		return false;
	}
}
bool X509_REQToPem(X509_REQ* x509_req, std::string& req_pem)
{
	try
	{
		unique_ptr<BIO, decltype(&::BIO_free)> bio(BIO_new(BIO_s_mem()), ::BIO_free);
		PEM_write_bio_X509_REQ(bio.get(), x509_req);
		BUF_MEM *tmp_buf = nullptr;
		BIO_get_mem_ptr(bio.get(), &tmp_buf);
		int req_len = tmp_buf->length;
		unique_ptr<char, decltype(&free)> req_buf((char*)calloc(1, req_len + 1), free);
		BIO_read(bio.get(), req_buf.get(), req_len);
		req_pem = req_buf.get();
		return true;
	}
	catch (...)
	{
		return false;
	}
}
//add end 2018-09-03 by renyl

//add begin 2018-09-16 by renyl, 以字符串形式导入证书
//Pem -- > EVP_PKEY
EVP_PKEY * PemToEVP_PKEY(const std::string & str_pem, const string& password)
{
	try
	{
		std::unique_ptr<BIO, decltype(&::BIO_free)> bio(BIO_new(BIO_s_mem()), ::BIO_free);
		BIO_write(bio.get(), str_pem.data(), str_pem.size());
		return PEM_read_bio_PrivateKey(bio.get(), nullptr, 0, password.empty() ? nullptr : (void*)password.c_str());
	}
	catch (...)
	{
		return nullptr;
	}
}
X509* PemToX509(const std::string& pem, const string& password)
{
	try
	{
		unique_ptr<BIO, decltype(&::BIO_free)> bio(BIO_new(BIO_s_mem()), ::BIO_free);
		BIO_write(bio.get(), (const void*)pem.data(), pem.size());
		return PEM_read_bio_X509(bio.get(), NULL, 0, password.empty() ? nullptr : (void*)password.c_str());
	}
	catch (...)
	{
		return nullptr;
	}
}
void ReleaseX509(X509* x)
{
	if (x != nullptr)
		X509_free(x);
}
//add end 2018-09-16 by renyl

CSSLInitializer CSSLInitializer::sm_instance;

const DWORD CSSLSessionPool::DEFAULT_ITEM_CAPACITY = CItemPool::DEFAULT_ITEM_CAPACITY;
const DWORD CSSLSessionPool::DEFAULT_ITEM_POOL_SIZE = CItemPool::DEFAULT_POOL_SIZE;
const DWORD CSSLSessionPool::DEFAULT_ITEM_POOL_HOLD = CItemPool::DEFAULT_POOL_HOLD;
const DWORD CSSLSessionPool::DEFAULT_SESSION_LOCK_TIME = 15 * 1000;
const DWORD CSSLSessionPool::DEFAULT_SESSION_POOL_SIZE = 600;
const DWORD CSSLSessionPool::DEFAULT_SESSION_POOL_HOLD = 600;

CSSLInitializer::CSSLInitializer()
{
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0
	sm_iLockNum = CRYPTO_num_locks();

	if (sm_iLockNum > 0)
		sm_pcsLocks = new CSimpleRWLock[sm_iLockNum];
	/*
	#ifdef _DEBUG
		CRYPTO_malloc_debug_init();
		CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
		CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	#endif
	*/
	CRYPTO_set_locking_callback(&ssl_lock_callback);
	CRYPTO_set_dynlock_create_callback(&ssl_lock_dyn_create_callback);
	CRYPTO_set_dynlock_destroy_callback(&ssl_lock_dyn_destroy_callback);
	CRYPTO_set_dynlock_lock_callback(&ssl_lock_dyn_callback);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#else
	OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, nullptr);
#endif
}

CSSLInitializer::~CSSLInitializer()
{
	CleanupThreadState();

#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0
	CONF_modules_free();
	ENGINE_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_2
	SSL_COMP_free_compression_methods();
#endif

	CRYPTO_set_locking_callback(nullptr);
	CRYPTO_set_dynlock_create_callback(nullptr);
	CRYPTO_set_dynlock_destroy_callback(nullptr);
	CRYPTO_set_dynlock_lock_callback(nullptr);

	if (sm_iLockNum > 0)
	{
		delete[] sm_pcsLocks;

		sm_pcsLocks = nullptr;
		sm_iLockNum = 0;
	}
#endif
}

void CSSLInitializer::CleanupThreadState(DWORD dwThreadID)
{
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0
	CRYPTO_THREADID tid = { nullptr, dwThreadID };

	CRYPTO_THREADID_current(&tid);
	ERR_remove_thread_state(&tid);
#else
	OPENSSL_thread_stop();
#endif
}

#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0

void CSSLInitializer::ssl_lock_callback(int mode, int n, const char *file, int line)
{
	mode & CRYPTO_LOCK
		? (mode & CRYPTO_READ
			? sm_pcsLocks[n].WaitToRead()
			: sm_pcsLocks[n].WaitToWrite())
		: (mode & CRYPTO_READ
			? sm_pcsLocks[n].ReadDone()
			: sm_pcsLocks[n].WriteDone());
}

CRYPTO_dynlock_value* CSSLInitializer::ssl_lock_dyn_create_callback(const char *file, int line)
{
	return new DynamicLock;
}

void CSSLInitializer::ssl_lock_dyn_callback(int mode, CRYPTO_dynlock_value* l, const char *file, int line)
{
	mode & CRYPTO_LOCK
		? (mode & CRYPTO_READ
			? l->cs.WaitToRead()
			: l->cs.WaitToWrite())
		: (mode & CRYPTO_READ
			? l->cs.ReadDone()
			: l->cs.WriteDone());
}

void CSSLInitializer::ssl_lock_dyn_destroy_callback(CRYPTO_dynlock_value* l, const char *file, int line)
{
	delete l;
}

#endif

BOOL CSSLContext::Initialize(EnSSLSessionMode enSessionMode, int iVerifyMode, LPCTSTR lpszPemCertFile, LPCTSTR lpszPemKeyFile, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath, HP_Fn_SNI_ServerNameCallback fnServerNameCallback)
{
	ASSERT(!IsValid());

	if (IsValid())
	{
		::SetLastError(ERROR_INVALID_STATE);
		return FALSE;
	}

	m_enSessionMode = enSessionMode;

	if (AddContext(iVerifyMode, lpszPemCertFile, lpszPemKeyFile, lpszKeyPasswod, lpszCAPemCertFileOrPath) == 0)
		m_sslCtx = GetContext(0);
	else
	{
		Cleanup();
		return FALSE;
	}

	SetServerNameCallback(fnServerNameCallback);

	return TRUE;
}

int CSSLContext::AddServerContext(int iVerifyMode, LPCTSTR lpszPemCertFile, LPCTSTR lpszPemKeyFile, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath)
{
	ASSERT(IsValid());

	if (!IsValid())
	{
		::SetLastError(ERROR_INVALID_STATE);
		return FALSE;
	}

	if (m_enSessionMode != SSL_SM_SERVER)
	{
		::SetLastError(ERROR_INVALID_OPERATION);
		return FALSE;
	}

	return AddContext(iVerifyMode, lpszPemCertFile, lpszPemKeyFile, lpszKeyPasswod, lpszCAPemCertFileOrPath);
}

int CSSLContext::AddContext(int iVerifyMode, LPCTSTR lpszPemCertFile, LPCTSTR lpszPemKeyFile, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath)
{
	int iIndex = -1;
	SSL_CTX* sslCtx = SSL_CTX_new(SSLv23_method());

	SSL_CTX_set_quiet_shutdown(sslCtx, 1);
	SSL_CTX_set_verify(sslCtx, iVerifyMode, nullptr);
	SSL_CTX_set_cipher_list(sslCtx, "ALL:!aNULL:!eNULL");

	if (m_enSessionMode == SSL_SM_SERVER)
	{
		static volatile ULONG s_session_id_context = 0;
		ULONG session_id_context = ::InterlockedIncrement(&s_session_id_context);

		SSL_CTX_set_session_id_context(sslCtx, (BYTE*)&session_id_context, sizeof(session_id_context));
	}

	if (!LoadCertAndKey(sslCtx, iVerifyMode, lpszPemCertFile, lpszPemKeyFile, lpszKeyPasswod, lpszCAPemCertFileOrPath))
		SSL_CTX_free(sslCtx);
	else
	{
		iIndex = (int)m_lsSslCtxs.size();
		m_lsSslCtxs.push_back(sslCtx);
	}

	return iIndex;
}

//#include "openssl/err.h"
BOOL CSSLContext::LoadCertAndKey(SSL_CTX* sslCtx, int iVerifyMode, LPCTSTR lpszPemCertFile, LPCTSTR lpszPemKeyFile, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath)
{
	USES_CONVERSION;

	if (lpszCAPemCertFileOrPath != nullptr)
	{
		LPCTSTR lpszCAPemCertFile = nullptr;
		LPCTSTR lpszCAPemCertPath = nullptr;

		if (!ATLPath::FileExists(lpszCAPemCertFileOrPath))
		{
			::SetLastError(ERROR_FILE_NOT_FOUND);
			return FALSE;
		}

		if (!ATLPath::IsDirectory(lpszCAPemCertFileOrPath))
			lpszCAPemCertFile = lpszCAPemCertFileOrPath;
		else
			lpszCAPemCertPath = lpszCAPemCertFileOrPath;

		if (!SSL_CTX_load_verify_locations(sslCtx, T2CA(lpszCAPemCertFile), T2CA(lpszCAPemCertPath)))
		{
			::SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}

		if (!SSL_CTX_set_default_verify_paths(sslCtx))
		{
			::SetLastError(ERROR_FUNCTION_FAILED);
			return FALSE;
		}

		if (m_enSessionMode == SSL_SM_SERVER && iVerifyMode & SSL_VM_PEER)
		{
			STACK_OF(X509_NAME)* caCertNames = SSL_load_client_CA_file(T2CA(lpszCAPemCertFileOrPath));

			if (caCertNames == nullptr)
			{
				::SetLastError(ERROR_EMPTY);
				return FALSE;
			}

			SSL_CTX_set_client_CA_list(sslCtx, caCertNames);
		}
	}

	if (lpszPemCertFile != nullptr)
	{
		if (!ATLPath::FileExists(lpszPemCertFile) ||
			ATLPath::IsDirectory(lpszPemCertFile))
		{
			::SetLastError(ERROR_FILE_NOT_FOUND);
			return FALSE;
		}

		if (lpszPemKeyFile == nullptr ||
			!ATLPath::FileExists(lpszPemKeyFile) ||
			ATLPath::IsDirectory(lpszPemKeyFile))
		{
			::SetLastError(ERROR_FILE_NOT_FOUND);
			return FALSE;
		}

		if (lpszKeyPasswod != nullptr)
			SSL_CTX_set_default_passwd_cb_userdata(sslCtx, (void*)T2CA(lpszKeyPasswod));

		if (!SSL_CTX_use_PrivateKey_file(sslCtx, T2CA(lpszPemKeyFile), SSL_FILETYPE_PEM))
		{
			////SSL_load_error_strings();
			//unsigned long n = ERR_get_error();
			//char buf[1024];
			//char* s = ERR_error_string(n, buf);

			::SetLastError(ERROR_INVALID_PASSWORD);
			return FALSE;
		}

		if (!SSL_CTX_use_certificate_chain_file(sslCtx, T2CA(lpszPemCertFile)))
		{
			::SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}

		if (!SSL_CTX_check_private_key(sslCtx))
		{
			::SetLastError(ERROR_INVALID_ACCESS);
			return FALSE;
		}
	}

	return TRUE;
}

//add begin 2018-09-16 by renyl, 以字符串形式导入证书
BOOL CSSLContext::InitializeFromString(EnSSLSessionMode enSessionMode, int iVerifyMode, LPCTSTR lpszPemCert, LPCTSTR lpszPemKey, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath, HP_Fn_SNI_ServerNameCallback fnServerNameCallback)
{
	ASSERT(!IsValid());

	if (IsValid())
	{
		::SetLastError(ERROR_INVALID_STATE);
		return FALSE;
	}

	m_enSessionMode = enSessionMode;

	if (AddContextFromString(iVerifyMode, lpszPemCert, lpszPemKey, lpszKeyPasswod, lpszCAPemCertFileOrPath) == 0)
		m_sslCtx = GetContext(0);
	else
	{
		Cleanup();
		return FALSE;
	}

	SetServerNameCallback(fnServerNameCallback);

	return TRUE;
}

int CSSLContext::AddServerContextFromString(int iVerifyMode, LPCTSTR lpszPemCert, LPCTSTR lpszPemKey, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath)
{
	ASSERT(IsValid());

	if (!IsValid())
	{
		::SetLastError(ERROR_INVALID_STATE);
		return FALSE;
	}

	if (m_enSessionMode != SSL_SM_SERVER)
	{
		::SetLastError(ERROR_INVALID_OPERATION);
		return FALSE;
	}

	return AddContextFromString(iVerifyMode, lpszPemCert, lpszPemKey, lpszKeyPasswod, lpszCAPemCertFileOrPath);
}
int CSSLContext::AddContextFromString(int iVerifyMode, LPCTSTR lpszPemCert, LPCTSTR lpszPemKey, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath)
{
	int iIndex = -1;
	SSL_CTX* sslCtx = SSL_CTX_new(SSLv23_method());

	SSL_CTX_set_quiet_shutdown(sslCtx, 1);
	SSL_CTX_set_verify(sslCtx, iVerifyMode, nullptr);
	SSL_CTX_set_cipher_list(sslCtx, "ALL:!aNULL:!eNULL");

	if (m_enSessionMode == SSL_SM_SERVER)
	{
		static volatile ULONG s_session_id_context = 0;
		ULONG session_id_context = ::InterlockedIncrement(&s_session_id_context);

		SSL_CTX_set_session_id_context(sslCtx, (BYTE*)&session_id_context, sizeof(session_id_context));
	}

	if (!LoadCertAndKeyFromString(sslCtx, iVerifyMode, lpszPemCert, lpszPemKey, lpszKeyPasswod, lpszCAPemCertFileOrPath))
		SSL_CTX_free(sslCtx);
	else
	{
		iIndex = (int)m_lsSslCtxs.size();
		m_lsSslCtxs.push_back(sslCtx);
	}

	return iIndex;
}
BOOL CSSLContext::LoadCertAndKeyFromString(SSL_CTX* sslCtx, int iVerifyMode, LPCTSTR lpszPemCert, LPCTSTR lpszPemKey, LPCTSTR lpszKeyPasswod, LPCTSTR lpszCAPemCertFileOrPath)
{
	USES_CONVERSION;

	if (lpszCAPemCertFileOrPath != nullptr)
	{
		LPCTSTR lpszCAPemCertFile = nullptr;
		LPCTSTR lpszCAPemCertPath = nullptr;

		if (!ATLPath::FileExists(lpszCAPemCertFileOrPath))
		{
			::SetLastError(ERROR_FILE_NOT_FOUND);
			return FALSE;
		}

		if (!ATLPath::IsDirectory(lpszCAPemCertFileOrPath))
			lpszCAPemCertFile = lpszCAPemCertFileOrPath;
		else
			lpszCAPemCertPath = lpszCAPemCertFileOrPath;

		if (!SSL_CTX_load_verify_locations(sslCtx, T2CA(lpszCAPemCertFile), T2CA(lpszCAPemCertPath)))
		{
			::SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}

		if (!SSL_CTX_set_default_verify_paths(sslCtx))
		{
			::SetLastError(ERROR_FUNCTION_FAILED);
			return FALSE;
		}

		if (m_enSessionMode == SSL_SM_SERVER && iVerifyMode & SSL_VM_PEER)
		{
			STACK_OF(X509_NAME)* caCertNames = SSL_load_client_CA_file(T2CA(lpszCAPemCertFileOrPath));

			if (caCertNames == nullptr)
			{
				::SetLastError(ERROR_EMPTY);
				return FALSE;
			}

			SSL_CTX_set_client_CA_list(sslCtx, caCertNames);
		}
	}

	if (lpszPemCert != nullptr)
	{
		if (lpszKeyPasswod != nullptr)
			SSL_CTX_set_default_passwd_cb_userdata(sslCtx, (void*)T2CA(lpszKeyPasswod));

		unique_ptr<EVP_PKEY, decltype(&ReleaseEVP_PKEY)> pkey(PemToEVP_PKEY(T2CA(lpszPemCert), T2CA(lpszKeyPasswod)), ReleaseEVP_PKEY);
		if (pkey == nullptr)
		{
			::SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}
				
		if (!SSL_CTX_use_PrivateKey(sslCtx, pkey.get()))
		{
			::SetLastError(ERROR_INVALID_PASSWORD);
			return FALSE;
		}

		unique_ptr<X509, decltype(&ReleaseX509)> x(PemToX509(T2CA(lpszPemCert), T2CA(lpszKeyPasswod)), ReleaseX509);
		//SSL_CTX_add_extra_chain_cert(sslCtx, x.get());	//证书链
		if(!SSL_CTX_use_certificate(sslCtx, x.get()))
		{
			::SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}

		if (!SSL_CTX_check_private_key(sslCtx))
		{
			::SetLastError(ERROR_INVALID_ACCESS);
			return FALSE;
		}
	}

	return TRUE;
}
//add end 2018-09-16 by renyl

void CSSLContext::Cleanup()
{
	if (IsValid())
	{
		int iCount = (int)m_lsSslCtxs.size();

		for (int i = 0; i < iCount; i++)
			SSL_CTX_free(m_lsSslCtxs[i]);

		m_lsSslCtxs.clear();
		m_sslCtx = nullptr;
	}

	m_fnServerNameCallback = nullptr;

	RemoveThreadLocalState();
}

void CSSLContext::SetServerNameCallback(Fn_SNI_ServerNameCallback fn)
{
	if (m_enSessionMode != SSL_SM_SERVER)
		return;

	m_fnServerNameCallback = fn;

	if (m_fnServerNameCallback == nullptr)
		return;

	ENSURE(SSL_CTX_set_tlsext_servername_callback(m_sslCtx, InternalServerNameCallback));
	ENSURE(SSL_CTX_set_tlsext_servername_arg(m_sslCtx, this));
}

int CSSLContext::InternalServerNameCallback(SSL* ssl, int* ad, void* arg)
{
	USES_CONVERSION;

	CSSLContext* pThis = (CSSLContext*)arg;
	ASSERT(pThis->m_fnServerNameCallback != nullptr);

	const char* lpszServerName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	if (lpszServerName == nullptr)
		return SSL_TLSEXT_ERR_NOACK;

	int iIndex = pThis->m_fnServerNameCallback(A2CT(lpszServerName));

	if (iIndex == 0)
		return SSL_TLSEXT_ERR_OK;

	if (iIndex < 0)
	{
		::SetLastError(ERROR_INVALID_NAME);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	SSL_CTX* sslCtx = pThis->GetContext(iIndex);

	if (sslCtx == nullptr)
	{
		::SetLastError(ERROR_INVALID_INDEX);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	SSL_set_SSL_CTX(ssl, sslCtx);

	return SSL_TLSEXT_ERR_OK;
}

SSL_CTX* CSSLContext::GetContext(int i) const
{
	SSL_CTX* sslCtx = nullptr;

	if (i >= 0 && i < (int)m_lsSslCtxs.size())
		sslCtx = m_lsSslCtxs[i];

	return sslCtx;
}

BOOL CSSLSession::WriteRecvChannel(const BYTE* pData, int iLength)
{
	ASSERT(pData && iLength > 0);

	BOOL isOK = TRUE;
	int bytes = BIO_write(m_bioRecv, pData, iLength);

	if (bytes > 0)
		ASSERT(bytes == iLength);
	else if (!BIO_should_retry(m_bioRecv))
		isOK = FALSE;

	return isOK;
}

BOOL CSSLSession::ReadRecvChannel()
{
	BOOL isOK = TRUE;
	int bytes = SSL_read(m_ssl, m_bufRecv.buf, m_pitRecv->Capacity());

	if (bytes > 0)
		m_bufRecv.len = bytes;
	else if (!IsFatalError(bytes))
		m_bufRecv.len = 0;
	else
		isOK = FALSE;

	if (isOK && m_enStatus == SSL_HSS_PROC && SSL_is_init_finished(m_ssl))
		m_enStatus = SSL_HSS_SUCC;

	return isOK;
}

BOOL CSSLSession::WriteSendChannel(const BYTE* pData, int iLength)
{
	ASSERT(IsReady());
	ASSERT(pData && iLength > 0);

	BOOL isOK = TRUE;
	int bytes = SSL_write(m_ssl, pData, iLength);

	if (bytes > 0)
		ASSERT(bytes == iLength);
	else if (IsFatalError(bytes))
		isOK = FALSE;

	return isOK;
}

BOOL CSSLSession::WriteSendChannel(const WSABUF pBuffers[], int iCount)
{
	ASSERT(pBuffers && iCount > 0);

	BOOL isOK = TRUE;

	for (int i = 0; i < iCount; i++)
	{
		const WSABUF& buffer = pBuffers[i];

		if (buffer.len > 0)
		{
			if (!WriteSendChannel((const BYTE*)buffer.buf, buffer.len))
			{
				isOK = FALSE;
				break;
			}
		}
	}

	return isOK;
}

BOOL CSSLSession::ReadSendChannel()
{
	if (BIO_pending(m_bioSend) == 0)
	{
		m_bufSend.len = 0;
		return TRUE;
	}

	BOOL isOK = TRUE;
	int bytes = BIO_read(m_bioSend, m_bufSend.buf, m_pitSend->Capacity());

	if (bytes > 0)
		m_bufSend.len = bytes;
	else if (BIO_should_retry(m_bioSend))
		m_bufSend.len = 0;
	else
		isOK = FALSE;

	return isOK;
}

CSSLSession* CSSLSession::Renew(const CSSLContext& sslCtx, LPCSTR lpszHostName)
{
	ASSERT(!IsValid());

	m_ssl = SSL_new(sslCtx.GetDefaultContext());
	m_bioSend = BIO_new(BIO_s_mem());
	m_bioRecv = BIO_new(BIO_s_mem());

	SSL_set_bio(m_ssl, m_bioRecv, m_bioSend);

	if (sslCtx.GetSessionMode() == SSL_SM_SERVER)
		SSL_accept(m_ssl);
	else
	{
		USES_CONVERSION;

		if (lpszHostName && lpszHostName[0] != 0 && !::IsIPAddress(A2CT(lpszHostName)))
			SSL_set_tlsext_host_name(m_ssl, lpszHostName);

		SSL_connect(m_ssl);
	}

	m_pitSend = m_itPool.PickFreeItem();
	m_pitRecv = m_itPool.PickFreeItem();
	m_bufSend.buf = (char*)m_pitSend->Ptr();
	m_bufRecv.buf = (char*)m_pitRecv->Ptr();
	m_enStatus = SSL_HSS_PROC;

	return this;
}

BOOL CSSLSession::Reset()
{
	BOOL isOK = FALSE;

	if (IsValid())
	{
		CCriSecLock locallock(m_csSend);

		if (IsValid())
		{
			m_enStatus = SSL_HSS_INIT;

			SSL_shutdown(m_ssl);
			SSL_free(m_ssl);

			m_itPool.PutFreeItem(m_pitSend);
			m_itPool.PutFreeItem(m_pitRecv);

			m_pitSend = nullptr;
			m_pitRecv = nullptr;
			m_ssl = nullptr;
			m_bioSend = nullptr;
			m_bioRecv = nullptr;
			m_dwFreeTime = ::TimeGetTime();

			isOK = TRUE;
		}
	}

	ERR_clear_error();

	return isOK;
}

inline BOOL CSSLSession::IsFatalError(int iBytes)
{
	int iErrorCode = SSL_get_error(m_ssl, iBytes);

	if (iErrorCode == SSL_ERROR_NONE ||
		iErrorCode == SSL_ERROR_WANT_READ ||
		iErrorCode == SSL_ERROR_WANT_WRITE ||
		iErrorCode == SSL_ERROR_WANT_CONNECT ||
		iErrorCode == SSL_ERROR_WANT_ACCEPT)
		return FALSE;

#ifdef _DEBUG
	char szBuffer[512];
#endif

	int i = 0;
	int iCode = iErrorCode;

	for (; iCode != SSL_ERROR_NONE; i++)
	{
#ifdef _DEBUG
		ERR_error_string_n(iCode, szBuffer, sizeof(szBuffer));
		TRACE("	> SSL Error: %d - %s\n", iCode, szBuffer);
#endif

		iCode = ERR_get_error();
	}

	if (iErrorCode == SSL_ERROR_SYSCALL && i == 1)
	{
		//ERR_clear_error();
		return FALSE;
	}

	return TRUE;
}

CSSLSession* CSSLSessionPool::PickFreeSession(LPCSTR lpszHostName)
{
	DWORD dwIndex;
	CSSLSession* pSession = nullptr;

	if (m_lsFreeSession.TryLock(&pSession, dwIndex))
	{
		if (::GetTimeGap32(pSession->GetFreeTime()) >= m_dwSessionLockTime)
			ENSURE(m_lsFreeSession.ReleaseLock(nullptr, dwIndex));
		else
		{
			ENSURE(m_lsFreeSession.ReleaseLock(pSession, dwIndex));
			pSession = nullptr;
		}
	}

	if (!pSession) pSession = CSSLSession::Construct(m_itPool);

	ASSERT(pSession);
	return pSession->Renew(m_sslCtx, lpszHostName);
}

void CSSLSessionPool::PutFreeSession(CSSLSession* pSession)
{
	if (pSession->Reset())
	{
		ReleaseGCSession();

		if (!m_lsFreeSession.TryPut(pSession))
			m_lsGCSession.PushBack(pSession);
	}
}

void CSSLSessionPool::ReleaseGCSession(BOOL bForce)
{
	::ReleaseGCObj(m_lsGCSession, m_dwSessionLockTime, bForce);
}

void CSSLSessionPool::Prepare()
{
	m_itPool.Prepare();
	m_lsFreeSession.Reset(m_dwSessionPoolSize);
}

void CSSLSessionPool::Clear()
{
	CSSLSession* pSession = nullptr;

	while (m_lsFreeSession.TryGet(&pSession))
		delete pSession;

	ENSURE(m_lsFreeSession.IsEmpty());
	m_lsFreeSession.Reset();

	ReleaseGCSession(TRUE);
	ENSURE(m_lsGCSession.IsEmpty());

	m_itPool.Clear();
}

//add begin 2018-09-03 by renyl, 生成客户端私钥, 证书请求
CSSLCertHelper::CSSLCertHelper()
{
	// openssl setup
	OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

	//seed PRNG
	string rand_str = GetRandString(128);
	RAND_seed(rand_str.c_str(), rand_str.length());
}

CSSLCertHelper::~CSSLCertHelper()
{
	//OPENSSL_cleanup();
}

bool CSSLCertHelper::CreatePemPrivateKeyAndCSR(int private_key_size, const std::string & private_key_password, const SubjectEntry & subj_entry,
	std::string & private_key, std::string & csr)
{
	try
	{
		unique_ptr<EVP_PKEY, decltype(&ReleaseEVP_PKEY)> pkey(CreateEVP_PKEY(private_key_size), ReleaseEVP_PKEY);
		if (pkey == nullptr)
			throw;

		unique_ptr<X509_REQ, decltype(&ReleaseX509_REQ)> req(CreateX509_REQ(pkey.get(), subj_entry), ReleaseX509_REQ);
		if (req == nullptr)
			throw;

		if (!EVP_PKEYToPem(pkey.get(), private_key_password, private_key))
			throw;

		if (!X509_REQToPem(req.get(), csr))
			throw;

		return true;
	}
	catch (...)
	{
		return false;
	}
}
//add end 2018-09-03 by renyl

//add begin 2018-09-10 by renyl, 生成MD5
std::string CSSLCertHelper::MakeMD5(const std::string& s)
{
	// 调用md5哈希  
	unsigned char mdStr[33] = { 0 };
	MD5((const unsigned char *)s.c_str(), s.length(), mdStr);

	// 哈希后的十六进制串 32字节  
	stringstream ss_d;
	for (int i = 0; i < 32; i++)
		ss_d << setw(2) << setfill('0') << hex << (int)mdStr[i];
	return ss_d.str();
}
//add end 2018-09-10 by renyl

//add begin 2018-09-15 by renyl, AES_256_CBC加解密

bool CSSLCertHelper::AES_256_CBC_Encrypt(const vector<byte>& src, const vector<byte>& key, const vector<byte> iv, vector<byte>& dst)
{
	unique_ptr<uint8_t[]> bkey = make_unique<uint8_t[]>(32);
	memset(bkey.get(), 0, 32);
	memcpy(bkey.get(), key.data(), key.size() > 32 ? 32 : key.size());

	unique_ptr<uint8_t[]> biv = make_unique<uint8_t[]>(AES_BLOCK_SIZE);
	memset(biv.get(), 0, AES_BLOCK_SIZE);
	memcpy(biv.get(), iv.data(), iv.size() > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : iv.size());

	//Create and initialise the context
	unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (ctx == nullptr)
		return false;

	//Initialise the encryption operation. 
	//IMPORTANT - ensure you use a key and IV size appropriate for your cipher In this example we are using 256 bit AES (i.e. a 256 bit key). 
	//The IV size for *most* modes is the same as the block size. For AES this is 128 bits
	if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, bkey.get(), biv.get()))
		return false;

	//Provide the message to be encrypted, and obtain the encrypted output.
	//EVP_EncryptUpdate can be called multiple times if necessary
	unique_ptr<uint8_t[]> encrypt_data = make_unique<uint8_t[]>(src.size() + AES_BLOCK_SIZE);
	int encrypt_size = 0;
	if (1 != EVP_EncryptUpdate(ctx.get(), encrypt_data.get(), &encrypt_size, src.data(), src.size()))
		return false;

	//Finalise the encryption. Further ciphertext bytes may be written at this stage.
	//默认启用padding: PKCS#7
	int padding_size = 0;
	if (1 != EVP_EncryptFinal_ex(ctx.get(), encrypt_data.get() + encrypt_size, &padding_size))
		return false;

	dst.assign(encrypt_data.get(), encrypt_data.get() + (encrypt_size + padding_size));

	return true;
}

bool CSSLCertHelper::AES_256_CBC_Decrypt(const vector<byte>& src, const vector<byte>& key, const vector<byte> iv, vector<byte>& dst)
{
	unique_ptr<uint8_t[]> bkey = make_unique<uint8_t[]>(32);
	memset(bkey.get(), 0, 32);
	memcpy(bkey.get(), key.data(), key.size() > 32 ? 32 : key.size());

	unique_ptr<uint8_t[]> biv = make_unique<uint8_t[]>(AES_BLOCK_SIZE);
	memset(biv.get(), 0, AES_BLOCK_SIZE);
	memcpy(biv.get(), iv.data(), iv.size() > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : iv.size());

	//Create and initialise the context
	unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (ctx == nullptr)
		return false;

	//Initialise the decryption operation. 
	//IMPORTANT - ensure you use a key and IV size appropriate for your cipher In this example we are using 256 bit AES (i.e. a 256 bit key). The
	//IV size for *most* modes is the same as the block size. For AES this is 128 bits
	if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, bkey.get(), biv.get()))
		return false;

	//Provide the message to be decrypted, and obtain the plaintext output.
	//EVP_DecryptUpdate can be called multiple times if necessary	
	unique_ptr<uint8_t[]> decrypt_data = make_unique<uint8_t[]>(src.size() + AES_BLOCK_SIZE);
	int decrypt_size = 0;
	if (1 != EVP_DecryptUpdate(ctx.get(), decrypt_data.get(), &decrypt_size, src.data(), src.size()))
		return false;

	//Finalise the decryption. Further plaintext bytes may be written at this stage.
	int padding_size = 0;
	if (1 != EVP_DecryptFinal_ex(ctx.get(), decrypt_data.get() + decrypt_size, &padding_size))
		return false;

	dst.assign(decrypt_data.get(), decrypt_data.get() + (decrypt_size + padding_size));

	return true;
}

//add end 2018-09-15 by renyl, AES-CBC加解密

CSSLCertHelper::_StaticConstructor CSSLCertHelper::_static_constructor_;

#endif
