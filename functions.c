#include<stdio.h>
#include <time.h>
#include <winsock2.h>
#include"definition.h"
extern char URL[URL_Length];//域名
extern IDTransform IDTransTable[AMOUNT];	//ID转换表
extern int IDcount;
extern int debug_level;
extern char *DEF_DNS_ADDRESS;
//开始界面
void disp_head()
{
	printf("***********************************************************\n");
	printf("* @Course Name: Course Design of Computer Network         *\n");
	printf("* @Name of Team members: Qin Haixu    Xiao Hanchi         *\n");
	printf("* @Teacher: Zhang Xuesong     @Class number: 2020219108   *\n");
	printf("* ------------------------------------------------------- *\n");
	printf("*                    DNS Relay Server                     *\n");
	printf("***********************************************************\n");
	printf("Command syntax : dnsrelay [-d | -dd] [dns-server-IP-addr]  \n");
}
//根据提供的参数设置打印调试信息级别和设置外部dns服务器地址
void proc_args(int argc, char* argv[])
{
	for (int i = 1; i < argc; ++i)
	{
		if (argv[i][0] == '-')
		{
			if (argv[i][1] == 'd' && argv[i][2] == 'd')
				debug_level = 2;
			else debug_level = 1;
		}
		else
		{
			printf("set dns server:%s\n", argv[i]);
			strcpy(DEF_DNS_ADDRESS, argv[i]);
		}
	}

	printf("debug level %d\n", debug_level);
}
//设置过期时间。参数是要设置的记录指针和生存时间
void set_ID_expire(IDTransform* record, int ttl)
{
	time_t now_time;
	now_time = time(NULL);
	record->expire_time = now_time + ttl;   //过期时间=现在时间+生存时间
}
//检查IDTransTable的record是否超时
int is_ID_expired(IDTransform* record)
{
	time_t now_time;
	now_time = time(NULL);
	if (now_time > record->expire_time)
		return 1;
	return 0;
}
void GetURL(char* buf)
{
	memset(URL, 0, URL_Length); //全用0初始化
	int len = strlen(buf);

	int i = 0, j, k = 0;
	//域名转换
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)//计数位
			for (j = buf[i], i++; j > 0; j--, i++, k++)
				URL[k] = buf[i];

		if (buf[i] != 0)
		{
			URL[k] = '.';
			k++;
		}
	}

	URL[k] = '\0';
}
//将请求ID转换为新的ID，并将信息写入ID转换表中
unsigned short ReplaceNewID(unsigned short OldID, SOCKADDR_IN temp, BOOL ifdone)
{
	int i;
	for (i = 1; i < AMOUNT; ++i)
	{
		//找到已过期或已完成请求的ID位置覆盖
		if (is_ID_expired(&IDTransTable[i]) == 1 || IDTransTable[i].done == TRUE)
		{
			IDTransTable[i].oldID = OldID;    //本来的id
			IDTransTable[i].client = temp;  //本来的sockaddr
			IDTransTable[i].done = ifdone;  //是否完成了请求
			set_ID_expire(&IDTransTable[i], EXPIRE_TIME);
			++IDcount;
			break;
		}
	}
	if (i == AMOUNT)    //没找到可写的地方
		return 0;
	return (unsigned short)i;	//以表中下标作为新的ID
}
void standard_print(char* buf, int length)
{
	unsigned char tage;
	printf("receive len=%d: ", length);
	for (int i = 0; i < length; i++)
	{
		tage = (unsigned char)buf[i];
		printf("%02x ", tage);
	}
	printf("\n");
}

