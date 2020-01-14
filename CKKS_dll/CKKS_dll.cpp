// CKKS_dll.cpp : 定义 DLL 应用程序的导出函数。
//
#include "info_androidhive_webmobilegroupchat_JniUtils.h"
#include<iostream>
using namespace std;


extern "C" JNIEXPORT jlong JNICALL Java_info_androidhive_webmobilegroupchat_JniUtils_nativeCreateCryptoContext
(JNIEnv *env, jclass jclass, jstring fileStorageDirectory, jint polyModulus, jint scale) {
	const char *directory = env->GetStringUTFChars(fileStorageDirectory, nullptr);
	CryptoContext *context = createCryptoContext(directory, polyModulus, scale);
	env->ReleaseStringUTFChars(fileStorageDirectory, directory);
	return reinterpret_cast<long>(context);
}

/*
 * Class:     info_androidhive_webmobilegroupchat_JniUtils
 * Method:    nativeReleaseCryptoContext
 * Signature: (J)V
 */
extern "C" JNIEXPORT void JNICALL Java_info_androidhive_webmobilegroupchat_JniUtils_nativeReleaseCryptoContext
(JNIEnv *env, jclass jclass, jlong contextHandle) {//JNIEnv *env, jclass jclass, jlong contextHandle
	releaseCryptoContext(reinterpret_cast<CryptoContext*>(contextHandle));
}

/*
 * Class:     info_androidhive_webmobilegroupchat_JniUtils
 * Method:    nativeEncrypt
 * Signature: (J[DLjava/lang/String;)Ljava/lang/String;
 */
extern "C" JNIEXPORT jstring JNICALL Java_info_androidhive_webmobilegroupchat_JniUtils_nativeEncrypt
(JNIEnv *env, jclass jclass, jlong contextHandle, jdoubleArray input, jstring ciphertextPath) {//JNIEnv *env, jclass jclass, jlong contextHandle, jdoubleArray input,jstring ciphertextPath
	jsize inputLength = env->GetArrayLength(input);
	jdouble *rawArray = env->GetDoubleArrayElements(input, nullptr);
	const char *ciphertext = env->GetStringUTFChars(ciphertextPath, nullptr);

	vector<double> inputVector(rawArray, rawArray + inputLength);
	env->ReleaseDoubleArrayElements(input, rawArray, JNI_ABORT);

	CryptoContext *context = reinterpret_cast<CryptoContext*>(contextHandle);
	jstring ciphertextString = env->NewStringUTF(context->encrypt(inputVector, ciphertext).c_str());
	env->ReleaseStringUTFChars(ciphertextPath, ciphertext);
	return ciphertextString;
}

/*
 * Class:     info_androidhive_webmobilegroupchat_JniUtils
 * Method:    nativeDecrypt
 * Signature: (JLjava/lang/String;)[D
 */
extern "C" JNIEXPORT jdoubleArray JNICALL Java_info_androidhive_webmobilegroupchat_JniUtils_nativeDecrypt
(JNIEnv *env, jclass jclass, jlong contextHandle, jstring input) {//JNIEnv *env, jclass jclass, jlong contextHandle, jstring input
	const char *rawInput = env->GetStringUTFChars(input, nullptr);
	CryptoContext *context = reinterpret_cast<CryptoContext*>(contextHandle);
	vector<double> output = context->decrypt(rawInput);
	env->ReleaseStringUTFChars(input, rawInput);
	jdoubleArray javaOutput = env->NewDoubleArray(output.size());
	env->SetDoubleArrayRegion(javaOutput, 0, output.size(), output.data());
	return javaOutput;
}

/*
 * Class:     info_androidhive_webmobilegroupchat_JniUtils
 * Method:    nativeLoadLocalKeys
 * Signature: (JLjava/lang/String;Ljava/lang/String;)Z
 */
extern "C" JNIEXPORT jboolean JNICALL Java_info_androidhive_webmobilegroupchat_JniUtils_nativeLoadLocalKeys
(JNIEnv *env, jclass jclass, jlong contextHandle, jstring publicKeyPath, jstring secretKeyPath) {//        JNIEnv *env,
	const char *publicKey = env->GetStringUTFChars(publicKeyPath, nullptr);
	const char *secretKey = env->GetStringUTFChars(secretKeyPath, nullptr);
	CryptoContext *context = reinterpret_cast<CryptoContext*>(contextHandle);
	bool result = context->loadLocalKeys(publicKey, secretKey);
	env->ReleaseStringUTFChars(publicKeyPath, publicKey);
	env->ReleaseStringUTFChars(secretKeyPath, secretKey);
	return result == true;
}

/*
 * Class:     info_androidhive_webmobilegroupchat_JniUtils
 * Method:    nativeGenerateKeys
 * Signature: (JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
//extern "C" JNIEXPORT jstring JNICALL Java_info_androidhive_webmobilegroupchat_JniUtils_nativeGenerateKeys
//(JNIEnv *env, jclass jclass, jlong contextHandle, jstring publicKeyPath, jstring secretKeyPath, jstring relinearizeKeyPath) {
//	const char *publicKey = env->GetStringUTFChars(publicKeyPath, nullptr);
//	const char *secretKey = env->GetStringUTFChars(secretKeyPath, nullptr);
//	const char *relinearizeKey = env->GetStringUTFChars(relinearizeKeyPath, nullptr);
//	CryptoContext *context = reinterpret_cast<CryptoContext*>(contextHandle);
//	jstring secretKeyString = env->NewStringUTF(context->generateKeys(publicKey, secretKey, relinearizeKey).c_str());
//	env->ReleaseStringUTFChars(publicKeyPath, publicKey);
//	env->ReleaseStringUTFChars(secretKeyPath, secretKey);
//	env->ReleaseStringUTFChars(relinearizeKeyPath, relinearizeKey);
//	return secretKeyString;
//
//}

