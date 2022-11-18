#include<stdio.h>
#include<WinSock2.h>
#include<stdlib.h>
#include<time.h>
#include"definition.h"
#include"functions.h"
#include"cache.h"
#pragma comment(lib, "ws2_32.lib")
IDTransform IDTransTable[AMOUNT];	//IDת����
char DEF_DNS_ADDRESS[16] = "192.168.31.1";
int IDcount = 0; //ת�����е���Ŀ����
char URL[URL_Length]; //����
int debug_level = 0;
SOCKET servSock, localSock;//�����׽��֣����ⲿ�׽���
SOCKADDR_IN serverName, localName;	//�ⲿDNS�ͱ���DNS�����׽��ֵ�ַ
SOCKADDR_IN client;
int Len_cli, Len_recv, Len_send;
char sendBuf[BUFSIZE]; //���ͻ���
char recvBuf[BUFSIZE]; //���ջ���
char* find;
void init_socket()
{
	//��ʼ�� DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//�����׽���
	servSock = socket(AF_INET, SOCK_DGRAM, 0);
	localSock = socket(AF_INET, SOCK_DGRAM, 0);

	//���׽ӿڶ�����Ϊ������
	int unBlock = 1;
	ioctlsocket(servSock, FIONBIO, (u_long FAR*) & unBlock);//���ⲿ�׽ӿ�����Ϊ������
	ioctlsocket(localSock, FIONBIO, (u_long FAR*) & unBlock);//�������׽ӿ�����Ϊ������
	if (localSock < 0)
	{
		if (debug_level >= 1)
			perror("create socket");
		exit(1);
	}

	//���׽���
	localName.sin_family = AF_INET;//IPV4
	localName.sin_port = htons(PORT);//�˿ں�
	localName.sin_addr.s_addr = INADDR_ANY;//�������� address
	serverName.sin_family = AF_INET;
	serverName.sin_port = htons(PORT);
	serverName.sin_addr.s_addr = inet_addr(DEF_DNS_ADDRESS);

	int reuse = 1;
	setsockopt(localSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));//�����׽��ֵ�ѡ��,������ֱ��ض˿ڱ�ռ�����

	//�󶨱��ط�������ַ	
	if (bind(localSock, (SOCKADDR*)&localName, sizeof(localName)))
	{
		printf("Bind 53 port failed.\n");
		exit(-1);
	}
	else
		printf("Bind 53 port success.\n");
}
//�ӱ�����ȡDNS��ѯ���ӻ����ȡ���͵��ⲿDNS��������ѯ
void receive_from_local()
{
	unsigned short NewID;
	unsigned short* pID;
	Len_cli = sizeof(client);
	memset(recvBuf, 0, BUFSIZE); //�����ջ����ʼ��

	//���ձ���DNS����
	Len_recv = recvfrom(localSock, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&client, &Len_cli);
	if (Len_recv > 0)
	{
		if (Len_recv == SOCKET_ERROR)	//������
		{
			printf("Recvfrom Failed: %s\n", strerror(WSAGetLastError()));
			return;
		}
		else
		{
			char* p = recvBuf + 12; //����DNS��ͷ��ָ�� ��Queries����
			GetURL(p);	//��ȡ����
			if (debug_level >= 1)
				printf("��ѯ����%s\n", URL);
			find = Find(URL); //��cache�в���
		}
		if (find==NULL)//cache�в�����
		{
			//IDת��
			pID = (unsigned short*)malloc(sizeof(unsigned short*));
			memcpy(pID, recvBuf, sizeof(unsigned short)); //����ǰ���ֽ�ΪID
			NewID = htons(ReplaceNewID(ntohs(*pID), client, FALSE));//IDת��
			if (ntohs(NewID) == 0)
			{
				if (debug_level >= 1)
					puts("Buffer full.");
			}
			else
			{
				memcpy(recvBuf, &NewID, sizeof(unsigned short));

				if (debug_level >= 1)
					printf("����δ��ѯ��������������ת������%s \n", URL);
				//��recvbufת����ָ�����ⲿDNS������
				Len_send = sendto(servSock, recvBuf, Len_recv, 0, (SOCKADDR*)&serverName, sizeof(serverName));
			}
			free(pID);
		}
		else //DNS�������д���
		{
			if (debug_level >= 1)
				printf("cache���� %s -> %s\n", URL, find);

			//������Ӧ����ͷ
			memcpy(sendBuf, recvBuf, Len_recv); //����������
			unsigned short AFlag = htons(0x8180); // 0x8180ΪDNS��Ӧ���ĵı�־Flags�ֶ�
			memcpy(&sendBuf[2], &AFlag, sizeof(unsigned short)); //�޸ı�־��Flags,�ƿ�ID�����ֽ�

			//�޸Ļش�����
			if (strcmp(find, "0.0.0.0") == 0)
			{
				AFlag = htons(0x0000);	//���ι��ܣ��ش���Ϊ0	
				printf("������վ������\n");
			}
			else
				AFlag = htons(0x0001);	//���������ܣ��ش���Ϊ1
			memcpy(&sendBuf[6], &AFlag, sizeof(unsigned short)); //�޸Ļش��¼��(Answer RRs)���ƿ�ID���ֽڡ�Flags���ֽڡ������¼�����ֽ�

			//����DNS��Ӧ����
			int curLen = 0; //���ϸ��µĳ���
			char answer[16];
			unsigned short Name = htons(0xc00c);//�����ֶ�
			memcpy(answer, &Name, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned short TypeA = htons(0x0001);  //����1 ��ʾIPV4��ַ
			memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned short ClassA = htons(0x0001);  //��ѯ�� 1 ��ʾ������Э��
			memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned long timeLive = htonl(0x7b);  //����ʱ��
			memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
			curLen += sizeof(unsigned long);	
				
			unsigned short IPLen = htons(0x0004);  //��Դ���ݳ���
			memcpy(answer + curLen, &IPLen, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned long IP = (unsigned long)inet_addr(find);  //��Դ���ݼ�IP inet_addrΪIP��ַת������
			memcpy(answer + curLen, &IP, sizeof(unsigned long));
			curLen += sizeof(unsigned long);
			curLen += Len_recv;

			//�����ĺ���Ӧ���ֹ�ͬ���DNS��Ӧ���Ĵ���sendbuf	
			memcpy(sendBuf + Len_recv, answer, sizeof(answer));

			//����DNS��Ӧ����
			Len_send = sendto(localSock, sendBuf, curLen, 0, (SOCKADDR*)&client, sizeof(client));

			char* p;
			p = sendBuf + Len_send - 4;
			if (debug_level >= 1)
				printf("���ؿͻ��� %s -> %u.%u.%u.%u\n", URL, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
		}
		printf("---------------------------------\n");
	}
}
//��Զ��DNS���ձ��Ĳ�ת��������
void receive_from_out()
{
	//���������ⲿDNS����������Ӧ����
	Len_recv = recvfrom(servSock, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&client, &Len_cli);
	if (Len_recv > -1)
	{
		if (debug_level >= 2)
			standard_print(recvBuf, Len_recv);
		//IDת��
		unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short*));
		memcpy(pID, recvBuf, sizeof(unsigned short)); //����ǰ���ֽ�ΪID
		int GetId = ntohs(*pID); //ntohs�Ĺ��ܣ��������ֽ���ת��Ϊ�����ֽ���
		unsigned short oID = htons(IDTransTable[GetId].oldID);
		memcpy(recvBuf, &oID, sizeof(unsigned short));

		//��IDת�����л�ȡ����DNS�����ߵ���Ϣ
		--IDcount;
		IDTransTable[GetId].done = TRUE;
		client = IDTransTable[GetId].client;

		int nquery = ntohs(*((unsigned short*)(recvBuf + 4))), nresponse = ntohs(*((unsigned short*)(recvBuf + 6)));    //����������ش����

		char* p = recvBuf + 12; //����DNS��ͷ��ָ��
		//��ȡÿ��������Ĳ�ѯurl
		for (int i = 0; i < nquery; ++i)
		{
			GetURL(p);    //��ôдurl��ֻ���¼���һ�������url
			while (*p > 0)  //��ȡ��ʶ��ǰ�ļ����������url
				p += (*p) + 1;
			p += 5; //����url�����Ϣ��ָ����һ������
		}
		

		if (nresponse > 0 && debug_level >= 1)
			printf("�յ���Ӧ���� %s \n", URL);
		char ip[16];//�ظ���ip��ַ

		//�����ظ�
		for (int i = 0; i < nresponse; ++i)
		{
			int ip1, ip2, ip3, ip4;
			if ((unsigned char)*p == 0xc0) //��ָ�������
				p += 2;
			else
			{
				//���ݼ�������url
				while (*p > 0)
					p += (*p) + 1;
				++p;    //ָ����������
			}
			unsigned short resp_type = ntohs(*(unsigned short*)p);  //�ظ�����
			p += 2;
			unsigned short resp_class = ntohs(*(unsigned short*)p); //�ظ���
			p += 2;
			unsigned short high = ntohs(*(unsigned short*)p);   //����ʱ���λ
			p += 2;
			unsigned short low = ntohs(*(unsigned short*)p);    //����ʱ���λ
			p += 2;
			int ttl = (((int)high) << 16) | low;    //�ߵ�λ��ϳ�����ʱ��
			int datalen = ntohs(*(unsigned short*)p);   //�������ݳ���
			p += 2;
			if (debug_level >= 2)
				printf("type %d class %d ttl %d\n", resp_type, resp_class, ttl);

			if (resp_type == 1) //��A���ͣ��ظ�����url��ip
			{
				memset(ip, 0, sizeof(ip));
				//��ȡ4��ip����
				ip1 = (unsigned char)*p++;
				ip2 = (unsigned char)*p++;
				ip3 = (unsigned char)*p++;
				ip4 = (unsigned char)*p++;

				sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
				if (debug_level >= 2)
					printf("ip %d.%d.%d.%d\n\n", ip1, ip2, ip3, ip4);
				// ������ⲿ�������н��ܵ���������Ӧ��IP
				insert(ip, URL);//���ظ���ip����Ӧurlд��DNSTable��
				if (debug_level >= 1)
					printf("������cache�С�����ip:%s url:%s\n",ip,URL);
				break;
			}
			else p += datalen;  //ֱ������
		}

		//��recvbufת���������ߴ�
		Len_send = sendto(localSock, recvBuf, Len_recv, 0, (SOCKADDR*)&client, sizeof(client));

		free(pID); //�ͷŶ�̬������ڴ�
		printf("---------------------------------\n");
	}
}
int main(int argc, char* argv[])
{

	disp_head();

	proc_args(argc, argv);//����debug_level���ⲿDNS��ַ

	init_socket();//����socket

	//��ʼ��IDת����
	for (int i = 0; i < AMOUNT; i++)
	{
		IDTransTable[i].oldID = 0;
		IDTransTable[i].done = TRUE;
		IDTransTable[i].expire_time = 0;
		memset(&(IDTransTable[i].client), 0, sizeof(SOCKADDR_IN));
	}

	read_pre_cache();

	while (1)//����������
	{
		receive_from_out();
		receive_from_local();
	}
	WSACleanup();
	return 0;
}
