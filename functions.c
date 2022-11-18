#include<stdio.h>
#include <time.h>
#include <winsock2.h>
#include"definition.h"
extern char URL[URL_Length];//����
extern IDTransform IDTransTable[AMOUNT];	//IDת����
extern int IDcount;
extern int debug_level;
extern char *DEF_DNS_ADDRESS;
//��ʼ����
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
//�����ṩ�Ĳ������ô�ӡ������Ϣ����������ⲿdns��������ַ
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
//���ù���ʱ�䡣������Ҫ���õļ�¼ָ�������ʱ��
void set_ID_expire(IDTransform* record, int ttl)
{
	time_t now_time;
	now_time = time(NULL);
	record->expire_time = now_time + ttl;   //����ʱ��=����ʱ��+����ʱ��
}
//���IDTransTable��record�Ƿ�ʱ
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
	memset(URL, 0, URL_Length); //ȫ��0��ʼ��
	int len = strlen(buf);

	int i = 0, j, k = 0;
	//����ת��
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)//����λ
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
//������IDת��Ϊ�µ�ID��������Ϣд��IDת������
unsigned short ReplaceNewID(unsigned short OldID, SOCKADDR_IN temp, BOOL ifdone)
{
	int i;
	for (i = 1; i < AMOUNT; ++i)
	{
		//�ҵ��ѹ��ڻ�����������IDλ�ø���
		if (is_ID_expired(&IDTransTable[i]) == 1 || IDTransTable[i].done == TRUE)
		{
			IDTransTable[i].oldID = OldID;    //������id
			IDTransTable[i].client = temp;  //������sockaddr
			IDTransTable[i].done = ifdone;  //�Ƿ����������
			set_ID_expire(&IDTransTable[i], EXPIRE_TIME);
			++IDcount;
			break;
		}
	}
	if (i == AMOUNT)    //û�ҵ���д�ĵط�
		return 0;
	return (unsigned short)i;	//�Ա����±���Ϊ�µ�ID
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

