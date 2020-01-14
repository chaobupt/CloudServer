#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <iostream>
#include <stdio.h>
#include <string>
#include <Winsock2.h>
#include <process.h>
#include "zip.h"
#include "unzip.h"

using namespace std;
#pragma comment (lib, "Ws2_32.lib")


ZRESULT AddFileToZip(const TCHAR *zipfn, const TCHAR *zename, const TCHAR *zefn)
{
	if (GetFileAttributes(zipfn) == 0xFFFFFFFF || (zefn != 0 && GetFileAttributes(zefn) == 0xFFFFFFFF))
		return ZR_NOFILE;
	// Expected size of the new zip will be the size of the old zip plus the size of the new file

	HANDLE hf = CreateFile(zipfn, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (hf == INVALID_HANDLE_VALUE)
		return ZR_NOFILE; DWORD size = GetFileSize(hf, 0);
	CloseHandle(hf);

	if (zefn != 0)
	{
		hf = CreateFile(zefn, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (hf == INVALID_HANDLE_VALUE)
			return ZR_NOFILE; size += GetFileSize(hf, 0);
		CloseHandle(hf);
	}

	size *= 2; // just to be on the safe side.


	HZIP hzsrc = OpenZip(zipfn, 0); if (hzsrc == 0) return ZR_READ;

	HZIP hzdst = CreateZip(0, size, 0);
	if (hzdst == 0) { CloseZip(hzsrc); return ZR_WRITE; }
	// hzdst is created in the system pagefile
	// Now go through the old zip, unzipping each item into a memory buffer, and adding it to the new one
	char *buf = 0;
	unsigned int bufsize = 0; // we'll unzip each item into this memory buffer
	ZIPENTRY ze;
	ZRESULT zr = GetZipItem(hzsrc, -1, &ze);
	int numitems = ze.index;
	if (zr != ZR_OK) { CloseZip(hzsrc); CloseZip(hzdst); return zr; }

	for (int i = 0; i < numitems; i++)
	{
		zr = GetZipItem(hzsrc, i, &ze);
		if (zr != ZR_OK) { CloseZip(hzsrc); CloseZip(hzdst); return zr; }

		if (stricmp(ze.name, zename) == 0) continue; // don't copy over the old version of the file we're changing

		if (ze.attr&FILE_ATTRIBUTE_DIRECTORY) { zr = ZipAddFolder(hzdst, ze.name); if (zr != ZR_OK) { CloseZip(hzsrc); CloseZip(hzdst); return zr; } continue; }

		if (ze.unc_size > (long)bufsize)
		{
			if (buf != 0) delete[] buf; bufsize = ze.unc_size * 2; buf = new char[bufsize];
		}

		zr = UnzipItem(hzsrc, i, buf, bufsize);
		if (zr != ZR_OK) { CloseZip(hzsrc); CloseZip(hzdst); return zr; }
		zr = ZipAdd(hzdst, ze.name, buf, bufsize); if (zr != ZR_OK) { CloseZip(hzsrc); CloseZip(hzdst); return zr; }
	}
	delete[] buf;
	// Now add the new file
	if (zefn != 0) { zr = ZipAdd(hzdst, zename, zefn); if (zr != ZR_OK) { CloseZip(hzsrc); CloseZip(hzdst); return zr; } }
	zr = CloseZip(hzsrc); if (zr != ZR_OK) { CloseZip(hzdst); return zr; }
	//
	// The new file has been put into pagefile memory. Let's store it to disk, overwriting the original zip
	zr = ZipGetMemory(hzdst, (void**)&buf, &size);
	if (zr != ZR_OK) { CloseZip(hzdst); return zr; }
	hf = CreateFile(zipfn, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE) { CloseZip(hzdst); return ZR_WRITE; }
	DWORD writ; WriteFile(hf, buf, size, &writ, 0); CloseHandle(hf);
	zr = CloseZip(hzdst); if (zr != ZR_OK) return zr;
	return ZR_OK;
}

void unzip(const TCHAR* filePath) {
	//解压photo.zip
	cout << "开始解压缩" << endl;
	HZIP hz = OpenZip(filePath, 0);
	char *unzipPath = "photo0";
	SetUnzipBaseDir(hz, unzipPath);

	ZIPENTRY ze;
	GetZipItem(hz, -1, &ze);
	int numitems = ze.index;
	for (int zi = 0; zi < numitems; zi++)
	{
		ZIPENTRY ze;
		GetZipItem(hz, zi, &ze);
		UnzipItem(hz, zi, ze.name);
	}
	CloseZip(hz);
	cout << "完成解压缩" << endl;
}
void add2Zip(const TCHAR *zename, const TCHAR *zefn) {
	cout << "开始添加" << endl;
	const TCHAR * zipPath = "D:\\gitSpace\\SEAL\\Release\\photo0.zip";
	AddFileToZip(zipPath, zename, zefn);
	cout << "完成添加" << endl;
}
//监听8120端口，接收Zip文件
unsigned int __stdcall recvFileThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		char localPath[26] = "D:\\gitSpace\\SEAL\\Release\\";
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

		unzip((const TCHAR *)filePath);

	}
	return 0;
}


//监听8121端口，发送文件
unsigned int __stdcall sendFileThread(void *port)
{
	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons((int)port);

	int ret = bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);

	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
		//char localPath[28] = "D:\\gitSpace\\recvFromClient\\";
		char localPath[26] = "D:\\gitSpace\\SEAL\\Release\\";
		char filename[20];  //文件名缓冲区
		char buffer[1024];  //文件缓冲区
		int nCount = 0;
		int nRecv = 0;

		if (nRecv = recv(sockConn, filename, 20, 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		string filenameString(filename);

		cout << "客户端请求的文件名:" << filenameString << endl;
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

	int ret = bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		//char localPath[28] = "D:\\gitSpace\\recvFromClient\\";
		char localPath[26] = "D:\\gitSpace\\SEAL\\Release\\";
		int nCount = 0;
		int nRecv = 0;

		//server自己生成文件存储路径
		char filename[] = "encryptedFeature%d.txt";
		sprintf(filename, "encryptedFeature%d.txt", i++);

		char * filePath = strcat(localPath, filename);
		cout << "存储文件路径：" << filePath << endl;
		FILE* fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, sizeof(buffer), 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
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

	int ret = bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	ret = listen(sockSrv, 5);
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	int i = 0;


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);

		char buffer[1024];  //文件缓冲区
		//char localPath[28] = "D:\\gitSpace\\recvFromClient\\";
		char localPath[26] = "D:\\gitSpace\\SEAL\\Release\\";
		const char* oldZipPath = "D:\\gitSpace\\SEAL\\Release\\photo0.zip";
		const char* newZipPath = "D:\\gitSpace\\SEAL\\Release\\photo1.zip";

		int nCount = 0;
		int nRecv = 0;
		char filenameLen[4];
		char * length = filenameLen;
		char filename[14];

		recv(sockConn, filenameLen, 4, 0);

		//cout << "客户端发送的文件名长度:" << *(int*)length<< endl;

		//接收客户端上传的文件名作为接收文件的存储路径
		if (nRecv = recv(sockConn, filename, sizeof(filename), 0) == SOCKET_ERROR)
		{
			cout << "接收文件名失败" << WSAGetLastError() << endl;
			return false;
		}
		cout << "客户端发送的文件名:" << filename << endl;
		char * filePath = strcat(localPath, filename);
		cout << "文件路径：" << filePath << endl;
		FILE *fp = fopen(filePath, "wb");

		cout << "开始接收文件" << endl;
		while ((nCount = recv(sockConn, buffer, sizeof(buffer), 0)) > 0) {
			fwrite(buffer, nCount, 1, fp);
		}
		cout << "接收完成" << endl;
		fclose(fp);
		closesocket(sockConn);

		//cout << "将ct文件添加至zip:" << endl;
		//char* filename2 = "file.txt";
		//add2Zip((const TCHAR *)filePath, (const TCHAR *)filename2);
	}
	return 0;
}





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


	Sleep(INFINITE);
	WSACleanup();

	return 0;
}