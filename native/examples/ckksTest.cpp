// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "CryptoContext.h"
#include "base64.h"

using namespace std;
using namespace seal;


string loadCiphertextFromFile(shared_ptr<SEALContext> context, const std::string &filePath, Ciphertext ciphertext)
{
	ifstream file(filePath, ios_base::binary);
	string keyString = "";
	string keyStringEncoded = "";

	if (file.is_open())
	{
		stringstream ss;
		ss << file.rdbuf();
		keyStringEncoded = ss.str();
		keyString = base64_decode(ss.str());
		ss.str(keyString);
		ciphertext.unsafe_load(context, ss);
	}
	return keyStringEncoded;
}

void ckksTest()
{
	print_example_banner("Example: CKKS Basics");
	string  fileStorageDirectory  = "D:\\gitSpace\\SEAL\\native\\sealTest";

	//自己本地生成
	//string ciphertext1 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertextx22.txt";
	//string ciphertext2 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertexty22.txt";
	//string publicKeyOutputPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\publicKey22.txt";
	//string secretKeyOutputPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\secretKey22.txt";
	//string relinearizeKeyOutputPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\relinearizeKey22.txt";

	//从AS生成的文件中读取
	string ciphertext1 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertextAS1.txt";
	string ciphertext2 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertextAS2.txt";
	string publicKeyOutputPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\publicKeyAS.txt";
	string secretKeyOutputPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\secretKeyAS.txt";
	string relinearizeKeyOutputPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\relinearizeKeyAS.txt";

	CryptoContext *context = createCryptoContext(fileStorageDirectory, 8192, 40);

	//生成密钥并保存至文件
	context->generateKeys(publicKeyOutputPath,secretKeyOutputPath,relinearizeKeyOutputPath);
	//从以上文件中获取密钥
	cout <<"哈哈哈哈"<< endl;
	context->loadLocalKeys(publicKeyOutputPath, secretKeyOutputPath);

	cout << "啦啦啦啦" << endl;
	string encryptedX ="";
	string encryptedY ="";

	vector<double> input1{ 0.04891288, 0.031262737, 0.030423492, 0.0616257 };
	cout << "Original Input vector1: " << endl;
	print_vector(input1, 4, 9);
	vector<double> input2{ 0.020476542, -0.08371191, -0.038826868, 6.062781E-4 };
	cout << "Original Input vector2: " << endl;
	print_vector(input2, 4, 9);


	Ciphertext cipher1, cipher2;
	//生成密文并保存至文件
	context->encrypt(input1, ciphertext1);
	context->encrypt(input2, ciphertext2);
	//从以上文件中获取密文
	encryptedX = loadCiphertextFromFile(context->m_context, ciphertext1, cipher1);
	encryptedY = loadCiphertextFromFile(context->m_context, ciphertext2, cipher2);

	//从AS中生成的密文文件中加载
	//encryptedX = loadCiphertextFromFile(context->m_context, ciphertext1, cipher1);
	//encryptedY = loadCiphertextFromFile(context->m_context, ciphertext2, cipher2);


	Plaintext plain1, plain2;
	vector<double> plain_out1;
	vector<double> plain_out2;
	cout << "哈哈哈哈" << endl;
	plain_out1 = context->decrypt(encryptedX);
	cout << "咦咦咦咦" << endl;
	plain_out2 = context->decrypt(encryptedY);
	cout << "Decrypted Input vector1: " << endl;
	print_vector(plain_out1, 4, 9);
	cout << "Decrypted Input vector1: " << endl;
	print_vector(plain_out2, 4, 9);


}