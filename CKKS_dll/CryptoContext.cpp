// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "CryptoContext.h"
#include "base64.h"
#include <sstream>
#include <fstream>

using namespace seal;
using namespace std;

/**
 * Takes a SEAL object and encodes it to a Base64 string
 * 获取一个SEAL对象并将其编码为Base64字符串
 * @param object The SEAL object to encode
 */
template <typename T>
static string encodeSealToBase64(const T &object)
{
	ostringstream ss;
	object.save(ss);
	return base64_encode(ss.str());
}

/**
 * Takes a SEAL key and saves it out to the device's file system
 * 获取一个SEAL密钥并将其保存到设备的文件系统中
 * @param filePath Path to save the file
 * @param key The key to save out
 */
template <typename T>
static void saveToFile(const string &filePath, T &key)
{
	string keyString = encodeSealToBase64(key);
	ofstream saveFile(filePath, ios_base::binary);
	saveFile.write(keyString.c_str(), keyString.size());
}

/**
 * Loads a SEAL key from the device's file system
 * 从设备的文件系统加载一个SEAL密钥
 * @param filePath Path to load the file from
 * @param key The key to load out into
 */
template <typename T>
static bool loadFromFile(shared_ptr<SEALContext> context, const string &filePath, T &key)
{
	ifstream file(filePath, ios_base::binary);
	if (file.is_open())
	{
		stringstream ss;
		ss << file.rdbuf();
		string keyString = base64_decode(ss.str());
		ss.str(keyString);
		cout << ss.tellg() << endl;
		key.unsafe_load(context, ss);
		return true;
	}
	return false;
}


CryptoContext::CryptoContext(const EncryptionParameters &parms)
	: m_parms(parms),
	m_scale(pow(2.0, 40)),
	m_context(SEALContext::Create(m_parms)),
	m_encoder(m_context),
	m_evaluator(m_context)


{
}

CryptoContext::~CryptoContext() {}


void CryptoContext::generateKeys(
	const std::string &publicKeyOutputPath,
	const std::string &secretKeyOutputPath,
	const std::string &relinearizeKeyOutputPath)
{
	KeyGenerator keygen(m_context);

	m_public_key = keygen.public_key();
	saveToFile(publicKeyOutputPath, m_public_key);

	m_secret_key = keygen.secret_key();
	saveToFile(secretKeyOutputPath, m_secret_key);

	RelinKeys ev_keys = keygen.relin_keys();
	saveToFile(relinearizeKeyOutputPath, ev_keys);
}


bool CryptoContext::loadLocalKeys(const std::string &publicKeyPath, const std::string &secretKeyPath)
{
	//if either public or secret key cannot be loaded all keys must be recreated
	return loadFromFile(m_context, secretKeyPath, m_secret_key);
	//return loadFromFile(m_context, secretKeyPath, m_secret_key) && loadFromFile(m_context, publicKeyPath, m_public_key);
}


string CryptoContext::encrypt(const vector<double> &input, const std::string ciphertextOutputPath)
{
	Plaintext plain;
	m_encoder.encode(input, m_scale, plain);
	Ciphertext encrypted;
	Encryptor encryptor(m_context, m_public_key);
	encryptor.encrypt(plain, encrypted);
	saveToFile(ciphertextOutputPath, encrypted);
	return encodeSealToBase64(encrypted);
}

vector<double> CryptoContext::decrypt(const string &input)
{
	size_t slots = input.size() / sizeof(double);
	string decoded = base64_decode(input);
	stringstream stream;
	stream.write(decoded.data(), decoded.size());
	Decryptor decryptor(m_context, m_secret_key);
	Plaintext plainOutput;
	Ciphertext cipher;
	cipher.unsafe_load(m_context, stream);
	decryptor.decrypt(cipher, plainOutput);
	vector<double> realOutput;
	m_encoder.decode(plainOutput, realOutput);
	return realOutput;
}

CryptoContext *createCryptoContext(const string &fileStorageDirectory, int polyModulus, int scale)
{
	// The coeff_modulus parameter below is secure up to polyModulus == 8192.
	if (polyModulus > 8192)
	{
		throw invalid_argument("insecure parameters");
	}

	EncryptionParameters parms(scheme_type::CKKS);
	parms.set_poly_modulus_degree(polyModulus);
	parms.set_coeff_modulus(CoeffModulus::Create(polyModulus, { 40, 40, 40, 40, 40 })); //([ciphertext] coefficient modulus);(密文)模量系数
	CryptoContext *context = new CryptoContext(parms);
	//context->m_scale = pow(2.0, scale);
	return context;
}

void releaseCryptoContext(CryptoContext *context)
{
	delete context;
}
