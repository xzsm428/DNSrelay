#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#define PORT 53   //�˿ں�53
#define BUFSIZE 1024 //����Ļ����С
#define URL_Length 64//URL��󳤶�
#define AMOUNT 1000
#define NOTFOUND 0 //û����cache���ҵ�
#define EXPIRE_TIME 10 //����ʱ��
typedef struct Translate//cache�ṹ
{
	char* IP;	//IP��ַ
	char* domain;	//����
	struct Translate* next;//��̽��
	struct Translate* prior;//ǰ�����
}Translate;
//IDת����ṹ
typedef struct
{
	unsigned short oldID; //ԭ��ID
	int done;	//����Ƿ���ɽ���
	SOCKADDR_IN client;		//�������׽��ֵ�ַ
	int expire_time; //��ʱʱ��
} IDTransform;
