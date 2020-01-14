// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include <string>
#include <vector>
#include <seal/seal.h>

/**
 * Handles all the complex SEAL operations for encryption and decryption and exposes a simple to use
 * interface.处理所有复杂的加密解密SEAL操作，并公开一个简单的使用接口
 */
class CryptoContext
{
public:
	/**
	 * The constructor which allocates all the resources for SEAL
	 * 为SEAL分配所有资源的构造函数
	 * @param parms EncryptionParameters to use for SEAL. createCryptoContext sets these already,
	 * but if the client wishes to use their own then they can call the constructor directly and
	 * provide their own parameters.
	 * 用于密封的加密参数。createCryptoContext已经设置好了，但是如果用户希望使用他们自己的，可以直接调用构造函数提供自己的参数。
	 * @param parms The parameters for SEAL to build off with
	 * @param fileStorageDirectory The directory for keys to be saved out to 保存密钥的目录
	 */
	CryptoContext(const seal::EncryptionParameters &parms);
	~CryptoContext();

	/**
	 *
	 * Generate a new set of keys and saves them to files.
	 * 生成一组新的密钥并将它们保存到文件中。
	 * @param publicKeyOutputPath The path for the public key to save to.
	 * @param secretKeyOutputPath The path for the secret key to save to.
	 * @param galoisKeyOutputPath The path for the Galois key to save to.
	 * @param galoisSingleStepKeyOutputPath The path for the Galois single step key to save to.
	 * @param relinearizeKeyOutputPath The path for the relinearize key to save to.
	 */
	void generateKeys(
		const std::string &publicKeyPath,
		const std::string &secretKeyPath,
		const std::string &relinearizeKeyPath);

	/**
 * Loads the public and secret keys which get saved from a call to generateKeys. These paths
 * must match the ones passed into generateKeys, and must be called before any encryption or
 * decryption take place. This is meant for subsequent runs of the app to speed up loading of
 * the public and private keys as key generation is very slow and they need to persist for
 * future runs. If this call fails that means either the keys don't exist, or they failed to
 * load into SEAL and must be (re)generated.
 * 加载从在generateKeys的调用中保存的公钥和私钥。这些路径必须与传递到generateKeys的路径匹配，并且必须在进行任何加密或解密之前调用。
 * 这意味着应用程序的后续运行将加速公钥和私钥的加载，因为密钥生成非常缓慢，而且它们需要在未来的运行中持续。
 * 如果这个调用失败，这意味着要么密钥不存在，要么它们未能加载到SEAL中，必须(重新)生成。
 * @param publicKeyOutputPath The path for the public key to load from.
 * @param secretKeyOutputPath The path for the secret key to load from.
 *
 * @return true if both keys load successfully, false otherwise
 */

	bool loadLocalKeys(const std::string &publicKeyPath, const std::string &secretKeyPath);

	std::string loadCiphertext(const std::string &ciphertextPath);

	/**
	 * Encrypts a vector of doubles and outputs a Base64 string
	 * 加密一个double向量并输出一个Base64字符串
	 * @param input A vector of doubles to encrypt
	 */
	std::string encrypt(const std::vector<double> &input, const std::string ciphertextOutputPath);

	/**
	 * Decrypts a Base64 encoded encrypted string and outputs a vector of doubles.
	 * 解密一个Base64编码的加密字符串并输出一个double型向量。
	 * @param input The Base64 encoded encrypted string
	 */
	std::vector<double> decrypt(const std::string &input);

public:
	seal::EncryptionParameters m_parms;
	double m_scale;
	std::shared_ptr<seal::SEALContext> m_context;
	seal::PublicKey m_public_key;
	seal::SecretKey m_secret_key;
	seal::CKKSEncoder m_encoder;
	seal::Evaluator m_evaluator;
};

/*
 * Creates and returns a CryptoContext. It handles all the encryption parameter setting without the
 * client needing to know how it's all done under the hood, not to mention AsureRun's use case
 * warranted a custom way of key generation.
 * 创建并返回一个加密上下文。它处理所有的加密参数设置，而客户端不需要知道它是如何在幕后完成的，更不用说AsureRun的用例保证了自定义密钥生成方式。
 * @param fileStorageDirectory The directory for keys to be saved out to
 * @param polyModulus The poly modulus for creating the SEAL context
 */
CryptoContext *createCryptoContext(const std::string &fileStorageDirectory, int polyModulus, int scale);

/*
 * Releases the CryptoContext's resources. C++ delete could also be called on it, but this is just
 * here as a counterpart to createCryptoContext.
 *
 * @param context The CryptoContext to release. It's also possible to just call delete on it, as
 * that's all that happens in this function anyway.
 */
void releaseCryptoContext(CryptoContext *context);
