#include<stdio.h>
#include<WinSock2.h>
#include<stdlib.h>
#include<time.h>
#include"definition.h"
#include"functions.h"
#include"cache.h"
#pragma comment(lib, "ws2_32.lib")
IDTransform IDTransTable[AMOUNT];	//ID转换表
char DEF_DNS_ADDRESS[16] = "192.168.31.1";
int IDcount = 0; //转换表中的条目个数
char URL[URL_Length]; //域名
int debug_level = 0;
SOCKET servSock, localSock;//本地套接字，和外部套接字
SOCKADDR_IN serverName, localName;	//外部DNS和本地DNS网络套接字地址
SOCKADDR_IN client;
int Len_cli, Len_recv, Len_send;
char sendBuf[BUFSIZE]; //发送缓存
char recvBuf[BUFSIZE]; //接收缓存
char* find;
void init_socket()
{
	//初始化 DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//创建套接字
	servSock = socket(AF_INET, SOCK_DGRAM, 0);
	localSock = socket(AF_INET, SOCK_DGRAM, 0);

	//将套接口都设置为非阻塞
	int unBlock = 1;
	ioctlsocket(servSock, FIONBIO, (u_long FAR*) & unBlock);//将外部套接口设置为非阻塞
	ioctlsocket(localSock, FIONBIO, (u_long FAR*) & unBlock);//将本地套接口设置为非阻塞
	if (localSock < 0)
	{
		if (debug_level >= 1)
			perror("create socket");
		exit(1);
	}

	//绑定套接字
	localName.sin_family = AF_INET;//IPV4
	localName.sin_port = htons(PORT);//端口号
	localName.sin_addr.s_addr = INADDR_ANY;//本地任意 address
	serverName.sin_family = AF_INET;
	serverName.sin_port = htons(PORT);
	serverName.sin_addr.s_addr = inet_addr(DEF_DNS_ADDRESS);

	int reuse = 1;
	setsockopt(localSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));//设置套接字的选项,避免出现本地端口被占用情况

	//绑定本地服务器地址	
	if (bind(localSock, (SOCKADDR*)&localName, sizeof(localName)))
	{
		printf("Bind 53 port failed.\n");
		exit(-1);
	}
	else
		printf("Bind 53 port success.\n");
}
//从本机读取DNS查询，从缓存读取或发送到外部DNS服务器查询
void receive_from_local()
{
	unsigned short NewID;
	unsigned short* pID;
	Len_cli = sizeof(client);
	memset(recvBuf, 0, BUFSIZE); //将接收缓存初始化

	//接收本地DNS请求
	Len_recv = recvfrom(localSock, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&client, &Len_cli);
	if (Len_recv > 0)
	{
		if (Len_recv == SOCKET_ERROR)	//错误反馈
		{
			printf("Recvfrom Failed: %s\n", strerror(WSAGetLastError()));
			return;
		}
		else
		{
			char* p = recvBuf + 12; //跳过DNS包头的指针 到Queries部分
			GetURL(p);	//获取域名
			if (debug_level >= 1)
				printf("查询——%s\n", URL);
			find = Find(URL); //在cache中查找
		}
		if (find==NULL)//cache中不存在
		{
			//ID转换
			pID = (unsigned short*)malloc(sizeof(unsigned short*));
			memcpy(pID, recvBuf, sizeof(unsigned short)); //报文前两字节为ID
			NewID = htons(ReplaceNewID(ntohs(*pID), client, FALSE));//ID转换
			if (ntohs(NewID) == 0)
			{
				if (debug_level >= 1)
					puts("Buffer full.");
			}
			else
			{
				memcpy(recvBuf, &NewID, sizeof(unsigned short));

				if (debug_level >= 1)
					printf("本地未查询到该域名，向外转发——%s \n", URL);
				//把recvbuf转发至指定的外部DNS服务器
				Len_send = sendto(servSock, recvBuf, Len_recv, 0, (SOCKADDR*)&serverName, sizeof(serverName));
			}
			free(pID);
		}
		else //DNS解析表中存在
		{
			if (debug_level >= 1)
				printf("cache命中 %s -> %s\n", URL, find);

			//构造响应报文头
			memcpy(sendBuf, recvBuf, Len_recv); //拷贝请求报文
			unsigned short AFlag = htons(0x8180); // 0x8180为DNS响应报文的标志Flags字段
			memcpy(&sendBuf[2], &AFlag, sizeof(unsigned short)); //修改标志域Flags,绕开ID的两字节

			//修改回答数域
			if (strcmp(find, "0.0.0.0") == 0)
			{
				AFlag = htons(0x0000);	//屏蔽功能：回答数为0	
				printf("不良网站，拦截\n");
			}
			else
				AFlag = htons(0x0001);	//服务器功能：回答数为1
			memcpy(&sendBuf[6], &AFlag, sizeof(unsigned short)); //修改回答记录数(Answer RRs)，绕开ID两字节、Flags两字节、问题记录数两字节

			//构造DNS响应部分
			int curLen = 0; //不断更新的长度
			char answer[16];
			unsigned short Name = htons(0xc00c);//域名字段
			memcpy(answer, &Name, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned short TypeA = htons(0x0001);  //类型1 表示IPV4地址
			memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned short ClassA = htons(0x0001);  //查询类 1 表示因特网协议
			memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned long timeLive = htonl(0x7b);  //生存时间
			memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
			curLen += sizeof(unsigned long);	
				
			unsigned short IPLen = htons(0x0004);  //资源数据长度
			memcpy(answer + curLen, &IPLen, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned long IP = (unsigned long)inet_addr(find);  //资源数据即IP inet_addr为IP地址转化函数
			memcpy(answer + curLen, &IP, sizeof(unsigned long));
			curLen += sizeof(unsigned long);
			curLen += Len_recv;

			//请求报文和响应部分共同组成DNS响应报文存入sendbuf	
			memcpy(sendBuf + Len_recv, answer, sizeof(answer));

			//发送DNS响应报文
			Len_send = sendto(localSock, sendBuf, curLen, 0, (SOCKADDR*)&client, sizeof(client));

			char* p;
			p = sendBuf + Len_send - 4;
			if (debug_level >= 1)
				printf("返回客户端 %s -> %u.%u.%u.%u\n", URL, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
		}
		printf("---------------------------------\n");
	}
}
//从远端DNS接收报文并转发到本机
void receive_from_out()
{
	//接收来自外部DNS服务器的响应报文
	Len_recv = recvfrom(servSock, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&client, &Len_cli);
	if (Len_recv > -1)
	{
		if (debug_level >= 2)
			standard_print(recvBuf, Len_recv);
		//ID转换
		unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short*));
		memcpy(pID, recvBuf, sizeof(unsigned short)); //报文前两字节为ID
		int GetId = ntohs(*pID); //ntohs的功能：将网络字节序转换为主机字节序
		unsigned short oID = htons(IDTransTable[GetId].oldID);
		memcpy(recvBuf, &oID, sizeof(unsigned short));

		//从ID转换表中获取发出DNS请求者的信息
		--IDcount;
		IDTransTable[GetId].done = TRUE;
		client = IDTransTable[GetId].client;

		int nquery = ntohs(*((unsigned short*)(recvBuf + 4))), nresponse = ntohs(*((unsigned short*)(recvBuf + 6)));    //问题个数；回答个数

		char* p = recvBuf + 12; //跳过DNS包头的指针
		//读取每个问题里的查询url
		for (int i = 0; i < nquery; ++i)
		{
			GetURL(p);    //这么写url里只会记录最后一个问题的url
			while (*p > 0)  //读取标识符前的计数跳过这个url
				p += (*p) + 1;
			p += 5; //跳过url后的信息，指向下一个报文
		}
		

		if (nresponse > 0 && debug_level >= 1)
			printf("收到响应报文 %s \n", URL);
		char ip[16];//回复的ip地址

		//分析回复
		for (int i = 0; i < nresponse; ++i)
		{
			int ip1, ip2, ip3, ip4;
			if ((unsigned char)*p == 0xc0) //是指针就跳过
				p += 2;
			else
			{
				//根据计数跳过url
				while (*p > 0)
					p += (*p) + 1;
				++p;    //指向后面的内容
			}
			unsigned short resp_type = ntohs(*(unsigned short*)p);  //回复类型
			p += 2;
			unsigned short resp_class = ntohs(*(unsigned short*)p); //回复类
			p += 2;
			unsigned short high = ntohs(*(unsigned short*)p);   //生存时间高位
			p += 2;
			unsigned short low = ntohs(*(unsigned short*)p);    //生存时间低位
			p += 2;
			int ttl = (((int)high) << 16) | low;    //高低位组合成生存时间
			int datalen = ntohs(*(unsigned short*)p);   //后面数据长度
			p += 2;
			if (debug_level >= 2)
				printf("type %d class %d ttl %d\n", resp_type, resp_class, ttl);

			if (resp_type == 1) //是A类型，回复的是url的ip
			{
				memset(ip, 0, sizeof(ip));
				//读取4个ip部分
				ip1 = (unsigned char)*p++;
				ip2 = (unsigned char)*p++;
				ip3 = (unsigned char)*p++;
				ip4 = (unsigned char)*p++;

				sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
				if (debug_level >= 2)
					printf("ip %d.%d.%d.%d\n\n", ip1, ip2, ip3, ip4);
				// 缓存从外部服务器中接受到的域名对应的IP
				insert(ip, URL);//将回复的ip及对应url写入DNSTable中
				if (debug_level >= 1)
					printf("保存至cache中———ip:%s url:%s\n",ip,URL);
				break;
			}
			else p += datalen;  //直接跳过
		}

		//把recvbuf转发至请求者处
		Len_send = sendto(localSock, recvBuf, Len_recv, 0, (SOCKADDR*)&client, sizeof(client));

		free(pID); //释放动态分配的内存
		printf("---------------------------------\n");
	}
}
int main(int argc, char* argv[])
{

	disp_head();

	proc_args(argc, argv);//设置debug_level和外部DNS地址

	init_socket();//设置socket

	//初始化ID转换表
	for (int i = 0; i < AMOUNT; i++)
	{
		IDTransTable[i].oldID = 0;
		IDTransTable[i].done = TRUE;
		IDTransTable[i].expire_time = 0;
		memset(&(IDTransTable[i].client), 0, sizeof(SOCKADDR_IN));
	}

	read_pre_cache();

	while (1)//服务器操作
	{
		receive_from_out();
		receive_from_local();
	}
	WSACleanup();
	return 0;
}
