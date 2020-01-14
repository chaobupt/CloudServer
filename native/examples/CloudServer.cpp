#include "CloudServer.h"
#include "jni.h"
#pragma comment (lib, "Ws2_32.lib")

#ifdef _WIN32
#define PATH_SEPARATOR ';'
#else
#define PATH_SEPARATOR ':'
#endif


vector<string> split(const string& str, const string& delim) {
	vector<string> res;
	if ("" == str) return res;
	//先将要切割的字符串从string类型转换为char*类型  
	char * strs = new char[str.length() + 1]; //不要忘了  
	strcpy(strs, str.c_str());

	char * d = new char[delim.length() + 1];
	strcpy(d, delim.c_str());

	char *p = strtok(strs, d);
	while (p) {
		string s = p; //分割得到的字符串转换为string类型  
		res.push_back(s); //存入结果数组  
		p = strtok(NULL, d);
	}

	return res;
}

void ckks(char * filename)
{
	print_example_banner("Example: CKKS Basics");
	EncryptionParameters parms(scheme_type::CKKS);

	size_t poly_modulus_degree = 8192; //degree of polynomial modulus 多项式模次数
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 })); //([ciphertext] coefficient modulus);(密文)模量系数

	auto context = SEALContext::Create(parms);
	print_parameters(context);

	/*********************************************************从AS生成的密钥文件中获取公钥、私钥********************************************************/
	string publicKeyPath = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\CKKS\\publicKeyAS.txt";
	string secretKeyPath = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\CKKS\\secretKeyAS.txt";
	string relinearizeKeyPath = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\CKKS\\relinearizeKeyAS.txt";
	PublicKey public_key;
	SecretKey secret_key;
	RelinKeys relin_keys;

	loadFromFile<PublicKey>(context, publicKeyPath, public_key);
	loadFromFile<SecretKey>(context, secretKeyPath, secret_key);
	loadFromFile<RelinKeys>(context, relinearizeKeyPath, relin_keys);

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	CKKSEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	//cout << "slot_count: " + slot_count << endl;

	/*********************************************************从AS生成的密文文件中获取密文*********************************************/
	Ciphertext encrypted_Ali, encrypted_Bob, encrypted_0, encrypted_1;

	string userFaceFeatureSet = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\userFaceFeatureSet\\";
	string ciphertextPath_Ali = userFaceFeatureSet + "encryptedFeature_Ali.txt";
	string ciphertextPath_Bob = userFaceFeatureSet + "encryptedFeature_Bob.txt";

	string basicDir = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\";
	string basicPath = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\";
	string ciphertextPath_0 = basicPath + filename;
	//string ciphertextPath_0 = basicPath + "encryptedFeature_0.txt";


	//从文件读取密文字符串
	loadCipherFromFile(context, ciphertextPath_Ali, encrypted_Ali);
	loadCipherFromFile(context, ciphertextPath_Bob, encrypted_Bob);
	loadCipherFromFile(context, ciphertextPath_0, encrypted_0);

	Plaintext plain0, plain1;
	vector<double> plain_out0;
	vector<double> plain_out1;

	decryptor.decrypt(encrypted_0, plain0);
	encoder.decode(plain0, plain_out0);
	print_vector(plain_out0, 10, 9);


	/*********************************************************Next, we compute (x1-x2)^2.**********************************/
	print_line(__LINE__);
	cout << "Compute ((x1-x2)^2)" << endl;

	Ciphertext Ali_minus_0_sq, Bob_minus_0_sq;
	evaluator.sub(encrypted_Ali, encrypted_0, Ali_minus_0_sq);
	evaluator.square_inplace(Ali_minus_0_sq);
	evaluator.relinearize_inplace(Ali_minus_0_sq, relin_keys);
	cout << "Scale of (x1-x2)^2 before rescale: " << log2(Ali_minus_0_sq.scale()) << " bits" << endl;
	evaluator.sub(encrypted_Bob, encrypted_0, Bob_minus_0_sq);
	evaluator.square_inplace(Bob_minus_0_sq);
	evaluator.relinearize_inplace(Bob_minus_0_sq, relin_keys);
	cout << "Scale of (x1-x2)^2 before rescale: " << log2(Bob_minus_0_sq.scale()) << " bits" << endl; 

	//将同态计算后的密文写入文件，以便发送给Social Provider
	vector<string> splitResult = split(filename, "_");
	saveToFile(basicDir + "Ali_"+ splitResult[1], Ali_minus_0_sq);
	saveToFile(basicDir + "Bob_" + splitResult[1], Bob_minus_0_sq);

	//将Ali_i.txt文件追加到FR.zip中
	cout << filename << "追加到photo0.zip中" << endl;
	//"minizip -a recvFromClient\\FR.zip Ali_0.txt"
	char cmd[43];
	sprintf(cmd, "minizip -a recvFromClient\\FR.zip %s", "Ali_" + splitResult[1]);
	system(cmd);
	cout << "Ali_" + splitResult[1] << "追加完毕" << endl;
	sprintf(cmd, "minizip -a recvFromClient\\FR.zip %s", "Bob_" + splitResult[1]);
	system(cmd);
	cout << "Bob_" + splitResult[1] << "追加完毕" << endl;

	//Decrypt and decode (x1-x2)^2
	Plaintext decrypted_result_Ali, decrypted_result_Bob;
	decryptor.decrypt(Ali_minus_0_sq, decrypted_result_Ali);
	vector<double> result_Ali;
	encoder.decode(decrypted_result_Ali, result_Ali);
	cout << "Computed result Ali:" << endl;
	print_vector(result_Ali, 10, 9);

	decryptor.decrypt(Bob_minus_0_sq, decrypted_result_Bob);
	vector<double> result_Bob;
	encoder.decode(decrypted_result_Bob, result_Bob);
	cout << "Computed result Bob:" << endl;
	print_vector(result_Bob, 10, 9);

}


/*******************************************线程函数**************************************************/

//监听8120端口，接收photo.zip文件
unsigned int __stdcall recvFileThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;

	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		char localPath[56] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\";
		int nCount = 0;
		int nRecv = 0;

		//server自己生成文件存储路径
		char filename[] = "photo%d.zip";
		//char* filenameLen;
		sprintf(filename, "photo%d.zip", i++);

		char * filePath = strcat(localPath, filename);
		cout << "存储文件路径：" << filePath << endl;
		FILE* fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, sizeof(buffer), 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
		fclose(fp);

		cout << "向Sender发送tag(文件名)：" << filename << endl;
		send(sockConn, filename, sizeof(filename), 0);

		closesocket(sockConn);

		//将photo.zip解压缩至文件夹photo下
		//unzip((const TCHAR *)filePath);
		//cout<<"解压缩完成！"<<endl;

	}
	return 0;
}


//监听8121端口，发送photo.zip文件
unsigned int __stdcall sendFileThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);

	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
		char localPath[56] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\";
		char filename[20];  //文件名缓冲区
		char buffer[1024];  //文件缓冲区
		int nCount = 0;
		int nRecv = 0;
		memset(filename, '\0', sizeof(filename));

		if (nRecv = recv(sockConn, filename, 20, 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		string filenameString(filename);

		cout << "客户端请求的文件名:" << filename << endl;
		cout << "长度:" << filenameString.data() << endl;

		char * filePath = strcat(localPath, filename);
		cout << "文件路径：" << filePath << endl;
		FILE *fp = fopen(filePath, "rb");

		cout << "开始发送文件" << endl;
		while ((nCount = fread(buffer, 1, sizeof(buffer), fp)) > 0)
		{
			send(sockConn, buffer, nCount, 0);
		}
		cout << "发送文件完毕" << endl;
		fclose(fp);
		closesocket(sockConn);
	}
	return 0;
}



//监听8122端口，接收加密特征
unsigned int __stdcall recvFeatureThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		char localPath[56] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\";
		int nCount = 0;
		int nRecv = 0;
		char filename[23];
		memset(filename, '\0', sizeof(filename));

		if (nRecv = recv(sockConn, filename, 22, 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		string filenameString(filename);
		cout << "客户端发送的文件名:" << filename << endl;
		char * filePath = strcat(localPath, filename);
		cout << "存储文件路径：" << filePath << endl;
		FILE* fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, sizeof(buffer), 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
		fclose(fp);

		ckks(filename);
		cout<<"同态计算完成！"<<endl;
		cout << "---------------------------------------------------------------------------" << endl;
		closesocket(sockConn);
	}
	return 0;
}

//监听8125端口，发送同态计算后的文件
unsigned int __stdcall sendFeatureThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);

	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
		char localPath[56] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\";

		char filename[7];  //文件名缓冲区
		char buffer[1024];  //文件缓冲区
		int nCount = 0;
		int nRecv = 0;
		memset(filename, '\0', sizeof(filename));

		cout << "监听到一个client连接请求：" << endl;
		if (nRecv = recv(sockConn, filename, 6, 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}

		string filenameString(filename);

		cout << "客户端请求的文件名:" << filename << endl;
		cout << "长度:" << filenameString.data() << endl;

		char * filePath = strcat(localPath, filename);
		cout << "文件路径：" << filePath << endl;
		FILE *fp = fopen(filePath, "rb");

		cout << "开始发送文件" << endl;
		while ((nCount = fread(buffer, 1, sizeof(buffer), fp)) > 0)
		{
			send(sockConn, buffer, nCount, 0);
		}
		cout << "发送文件完毕" << endl;
		fclose(fp);
		closesocket(sockConn);
	}
	return 0;
}

//监听8123端口，接收co-user的ct文件
unsigned int __stdcall recvCtThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		char localPath[56] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\";
		int nCount = 0;
		int nRecv = 0;
		char filename[12];
		memset(filename, '\0', sizeof(filename));

		if (nRecv = recv(sockConn, filename, 11, 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		string filenameString(filename);	
		cout << "客户端发送的文件名:" <<filename << endl;
		char * filePath = strcat(localPath, filename);
		cout << "文件路径：" << filePath << endl;
		FILE *fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, 1024, 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
		fclose(fp);

		cout<<filename<<"追加到photo0.zip中"<<endl;
		//"minizip -a recvFromClient\\photo0.zip recvFromClient\\cti_Bob.txt"
		char cmd[64];
		sprintf(cmd, "minizip -a recvFromClient\\photo0.zip %s", filenameString);
		system(cmd);
		cout << filenameString << "追加完毕" << endl;
		closesocket(sockConn);
	}
	return 0;
}

//监听8124端口，接收注册人脸的加密特征文件
unsigned int __stdcall recvRegisterFeatureThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		char localPath[75] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\userFaceFeatureSet\\";
		int nCount = 0;
		int nRecv = 0;
		char filename[25];
		memset(filename, '\0', sizeof(filename));

		if (nRecv = recv(sockConn, filename, sizeof(filename), 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		string filenameString(filename);
		cout << "客户端发送的文件名:" << filename << endl;
		char * filePath = strcat(localPath, filename);
		cout << "文件路径：" << filePath << endl;
		FILE *fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, 1024, 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
		fclose(fp);
		closesocket(sockConn);
	}
	return 0;
}


//监听8126端口，从Social Provider接收更新密钥MHOO_UK.txt
unsigned int __stdcall recvUKThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = ::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		char localPath[63] = "D:\\gitSpace\\SEAL\\native\\bin\\x64\\Release\\recvFromClient\\photo0\\";
		int nCount = 0;
		int nRecv = 0;
		char filename[12];
		memset(filename, '\0', sizeof(filename));

		if (nRecv = recv(sockConn, filename, 11, 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		string filenameString(filename);
		cout << "客户端发送的文件名:" << filename << endl;
		char * filePath = strcat(localPath, filename);
		cout << "文件路径：" << filePath << endl;
		FILE *fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, 1024, 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
		fclose(fp);

		//TODO: 接收到uk.txt, 更新密文ct0.txt -> 生成ctv0.txt, C++调用java
		/***************************************C++调用java开始******************************************/
		cout << "C++调用java开始：" << endl;
		//system("calc");

		char cmd[70];
		char* pkFile = "MHOO_PK.txt";
		char* ct0File = "ct0.txt";
		char* ukFile = filename;
		sprintf(cmd, "java -jar MHOOCTUpdate.jar %s %s %s", pkFile, ct0File, ukFile);
		system(cmd);
		cout << "C++调用java结束！" << endl;
		/***************************************C++调用java结束******************************************/
		cout << filename << "追加到photo0.zip中" << endl;
		//"minizip -a recvFromClient\\photo0.zip recvFromClient\\cti_Bob.txt"
		char addcmd[64] = "minizip -a recvFromClient\\photo0.zip ctv0.txt";
		system(addcmd);
		cout << "ctv0.txt" << "追加完毕" << endl;

		//将文件夹重新压缩成新的XXX.zip， 向sender返回新的压缩包的文件名
		char* repostPhoto = "photo0.zip";
		cout << "向Sender发送新的tag(文件名)：" << repostPhoto << endl;
		send(sockConn, repostPhoto, 10, 0);
		closesocket(sockConn);
	}
	return 0;
}



/***********************************************主程序**********************************************/
int main()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		return -1;
	}


	_beginthreadex(NULL, 0, recvFeatureThread, (void *)8122, 0, NULL); //接收从客户端发送的加密特征
	_beginthreadex(NULL, 0, recvFileThread, (void *)8120, 0, NULL); //接收从客户端发送的文件
	_beginthreadex(NULL, 0, sendFileThread, (void *)8121, 0, NULL); //向客户端发送请求的文件
	_beginthreadex(NULL, 0, recvCtThread, (void *)8123, 0, NULL); //接收co-user的cti文件
	_beginthreadex(NULL, 0, recvRegisterFeatureThread, (void *)8124, 0, NULL); //接收注册用户人脸特征文件
	_beginthreadex(NULL, 0, recvUKThread, (void *)8126, 0, NULL); //接收Social Provider发送的更新密钥MHOO_UK.txt
	_beginthreadex(NULL, 0, sendFeatureThread, (void *)8125, 0, NULL); //向Social provider发送同态计算后的特征文件

	Sleep(INFINITE);
	WSACleanup();

	return 0;
}