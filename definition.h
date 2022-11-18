#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#define PORT 53   //端口号53
#define BUFSIZE 1024 //最大报文缓存大小
#define URL_Length 64//URL最大长度
#define AMOUNT 1000
#define NOTFOUND 0 //没有在cache中找到
#define EXPIRE_TIME 10 //过期时间
typedef struct Translate//cache结构
{
	char* IP;	//IP地址
	char* domain;	//域名
	struct Translate* next;//后继结点
	struct Translate* prior;//前驱结点
}Translate;
//ID转换表结构
typedef struct
{
	unsigned short oldID; //原有ID
	int done;	//标记是否完成解析
	SOCKADDR_IN client;		//请求者套接字地址
	int expire_time; //超时时间
} IDTransform;
