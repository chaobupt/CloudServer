// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "base64.h"

using namespace std;
using namespace seal;


static string loadCipherFromFile(shared_ptr<SEALContext> context, const string &filePath, Ciphertext &ciphertext)
{
	ifstream file(filePath, ios_base::binary);
	string cipherString = "";
	string cipherStringEncoded = "";
	if (file.is_open())
	{
		stringstream ss;
		ss << file.rdbuf();
		cipherStringEncoded = ss.str();
		cipherString = base64_decode(ss.str());
		ss.str(cipherString);
		ciphertext.unsafe_load(context, ss);
	}
	return cipherString;
}

template <typename T>
static string loadFromFile(shared_ptr<SEALContext> context, const string &filePath, T &key)
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
		key.unsafe_load(context, ss);
	}
	return keyStringEncoded;
}

//template <typename T>
//static bool loadFromFile(shared_ptr<SEALContext> context, const string &filePath, T &key)
//{
//	ifstream file(filePath, ios_base::binary);
//	if (file.is_open())
//	{
//		stringstream ss;
//		ss << file.rdbuf();
//		string keyString = base64_decode(ss.str()); //error
//		ss.str(keyString);
//		key.unsafe_load(context, ss);
//		return true;
//	}
//	return false;
//}


template <typename T>
static string encodeSealToBase64(const T &object)
{
	ostringstream ss;
	object.save(ss);
	return base64_encode(ss.str());
}

template <typename T>
static void saveToFile(const string &filePath, T &key)
{
	string keyString = encodeSealToBase64(key);
	ofstream saveFile(filePath, ios_base::binary);
	saveFile.write(keyString.c_str(), keyString.size());
}




void ckks2()
{
	print_example_banner("Example: CKKS Basics");

	EncryptionParameters parms(scheme_type::CKKS);

	size_t poly_modulus_degree = 8192; //degree of polynomial modulus 多项式模次数
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 })); //([ciphertext] coefficient modulus);(密文)模量系数

	auto context = SEALContext::Create(parms);
	print_parameters(context);


	/*********************************************************从AS生成的密钥文件中获取公钥、私钥********************************************************/
	string publicKeyPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\publicKeyAS.txt";
	string secretKeyPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\secretKeyAS.txt";
	string relinearizeKeyPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\relinearizeKeyAS.txt";
	PublicKey public_key;
	SecretKey secret_key;
	RelinKeys relin_keys;
	string publicKeyString = loadFromFile<PublicKey>(context, publicKeyPath, public_key);
	cout<<"哈哈哈哈"<<endl;
	string secretKeyString = loadFromFile<SecretKey>(context, secretKeyPath, secret_key);
	cout << "啦啦啦啦" << endl;
	string relinKeysString = loadFromFile<RelinKeys>(context, relinearizeKeyPath, relin_keys);


	loadFromFile<PublicKey>(context, publicKeyPath, public_key);
	loadFromFile<SecretKey>(context, secretKeyPath, secret_key);
	loadFromFile<RelinKeys>(context, relinearizeKeyPath, relin_keys);


	/************************************************************自己本地生成密钥然后读取*****************************************************/
	//string publicKeyPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\publicKey11.txt";
	//string secretKeyPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\secretKey11.txt";
	//string relinearizeKeyPath = "D:\\gitSpace\\SEAL\\native\\sealTest\\relinearizeKey1.txt";
	//KeyGenerator keygen(context);
	//auto public_key = keygen.public_key();
	//auto secret_key = keygen.secret_key();
	//auto relin_keys = keygen.relin_keys();
	//saveToFile(publicKeyPath, public_key);
	//saveToFile(secretKeyPath, secret_key);
	//saveToFile(relinearizeKeyPath, relin_keys);

	//string publicKeyString = loadFromFile<PublicKey>(context, publicKeyPath, public_key);
	//string secretKeyString = loadFromFile<SecretKey>(context, secretKeyPath, secret_key);
	//string relinKeysString = loadFromFile<RelinKeys>(context, relinearizeKeyPath, relin_keys);
	//end


	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);				
	Decryptor decryptor(context, secret_key);

	CKKSEncoder encoder(context);				
	size_t slot_count = encoder.slot_count();

	vector<double> input1{ 0.04891288, 0.031262737, 0.030423492, 0.0616257 };
	cout << "Input vector1: " << endl;
	print_vector(input1, 4, 9); 
	vector<double> input2{ 0.020476542, -0.08371191, -0.038826868, 6.062781E-4 };
	cout << "Input vector2: " << endl;
	print_vector(input2, 4, 9); 


	/*********************************************************从AS生成的密文文件中获取密文*********************************************/
	Ciphertext x1_encrypted, x2_encrypted;
	string ciphertext1 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertextAS1.txt";
	string ciphertext2 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertextAS2.txt";
	//从文件读取密文字符串
	string cipher1 = loadCipherFromFile(context, ciphertext1, x1_encrypted);
	string cipher2 = loadCipherFromFile(context, ciphertext2, x2_encrypted);

	/*********************************************************从文件获取自己本地生成的密文*********************************************/
	//Ciphertext x1_encrypted, x2_encrypted;
	//string ciphertext1 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertextx11.txt";
	//string ciphertext2 = "D:\\gitSpace\\SEAL\\native\\sealTest\\ciphertexty11.txt";
	//Plaintext x1_plain, x2_plain;
	//double scale = pow(2.0, 40);			
	//cout << "Encode input vector1." << endl;
	//encoder.encode(input1, scale, x1_plain);
	//encoder.encode(input2, scale, x2_plain);
	//encryptor.encrypt(x1_plain, x1_encrypted);	
	//encryptor.encrypt(x2_plain, x2_encrypted);	
	//saveToFile(ciphertext1, x1_encrypted);
	//saveToFile(ciphertext2, x2_encrypted);
	//string cipher1 = loadCipherFromFile(context, ciphertext1, x1_encrypted);
 //   string cipher2 = loadCipherFromFile(context, ciphertext2, x2_encrypted);
	//end


	Plaintext plain1, plain2;
	vector<double> plain_out1;
	vector<double> plain_out2;

	decryptor.decrypt(x1_encrypted, plain1);
	decryptor.decrypt(x2_encrypted, plain2);
	encoder.decode(plain1, plain_out1);
	encoder.decode(plain1, plain_out1);
	print_vector(plain_out1, 4, 9);
	print_vector(plain_out2, 4, 9);


	/*********************************************************Next, we compute (x1-x2)^2.**********************************/

	print_line(__LINE__);
	cout << "Compute ((x1-x2)^2)" << endl;

	Ciphertext x1_minus_x2_sq;
	evaluator.sub(x1_encrypted, x2_encrypted, x1_minus_x2_sq);
	evaluator.square_inplace(x1_minus_x2_sq);

	evaluator.relinearize_inplace(x1_minus_x2_sq, relin_keys);
	cout << "Scale of (x1-x2)^2 before rescale: " << log2(x1_minus_x2_sq.scale())<< " bits" << endl;


	//测试
	cout << x1_minus_x2_sq.data(0) << endl; //000001DF9A560080
	cout << x1_minus_x2_sq.size()<< endl; //2
	cout << x1_minus_x2_sq.coeff_mod_count() << endl; //4
	cout << x1_minus_x2_sq.poly_modulus_degree() << endl; //8192

	for (size_t i = 0; i < 10; i++)
	{
		cout << x1_minus_x2_sq[i] << endl;
	}

	//Decrypt and decode (x1-x2)^2
	cout << "Expected result:" << endl;
	vector<double> true_result;
	for (size_t i = 0; i < slot_count; i++)
	{
		double x1 = input1[i];
		double x2 = input2[i];
		true_result.push_back((x1 - x2)*(x1 - x2));
	}
	print_vector(true_result, 4, 9);

	Plaintext decrypted_result;
	//decryption of x1_minus_x2_sq
	decryptor.decrypt(x1_minus_x2_sq, decrypted_result);

	vector<double> result;
	encoder.decode(decrypted_result, result);
	cout << "Computed result:" << endl;
	print_vector(result, 4, 9);

}