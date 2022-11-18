#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"definition.h"
extern int debug_level;
Translate* head, *start, *end;
int cacheSize = 0;
void createcache(char *ip,char* url)//ͷ�ڵ�,�������� 
{
	head = (struct Translate*)malloc(sizeof(struct Translate));
	head->next = NULL;
	head->prior = NULL;
	head->IP = ip;
	head->domain = url;
	end = head;
	cacheSize++;
}
void insert(char* ip, char* url)//���� β�巨
{
	if (cacheSize < AMOUNT)//cache�л��п�λ���ӵ���������
	{
		struct Translate* pTemp = (Translate*)malloc(sizeof(struct Translate));
		pTemp->IP = (char*)malloc(sizeof(char)*64);
		pTemp->domain = (char*)malloc(sizeof(char) * 64);
		strcpy(pTemp->IP, ip);
		strcpy(pTemp->domain, url);
		pTemp->next = NULL;
		pTemp->prior = end;
		end->next = pTemp;
		end = end->next;
		cacheSize++;
	}
	else//cache��û��λ LRU ��ɾ���
	{
		struct Translate* temp = start->next;
		while (temp->next)
		{
			if (strcmp(temp->domain, url) == 0)//����url֮ǰ�Ѿ���д��
				break;
			temp = temp->next;
		}
		if (temp->next == NULL)//urlû��д�� ɾ�����ټ�
		{
			temp = start->next;
			start->next = temp->next;
			free(temp);
			struct Translate* pTemp = (struct Translate*)malloc(sizeof(struct Translate));
			pTemp->IP = (char*)malloc(sizeof(char) * 64);
			pTemp->domain = (char*)malloc(sizeof(char) * 64);
			strcpy(pTemp->IP, ip);
			strcpy(pTemp->domain, url);
			pTemp->next = NULL;
			pTemp->prior = end;
			end->next = pTemp;
			end = end->next;
		}
		else//����url������Ų�����ȥ 
		{
			struct Translate* prior_node = temp->prior;
			prior_node->next = temp->next;
			temp->next = NULL;
			temp->prior = end;
			end->next = temp;
			end = end->next;
		}
	}
}
void read_pre_cache()//��ȡdnsrelay.txt
{
	int i = 0, j = 0;
	FILE* fp = fopen("dnsrelay.txt", "r");
	if (!fp)
	{
		printf("Open file failed.\n");
		exit(-1);
	}
	char* Temp[AMOUNT];
	while (i < AMOUNT - 1)//ʵ�ְ�ÿһ�зֿ��Ĳ���
	{
		Temp[i] = (char*)malloc(sizeof(char) * 200);
		if (fgets(Temp[i], 1000, fp) == NULL)//���������߶������������ͷ���NULL��
			break;
		i++;
	}
	if (i == AMOUNT - 1)
		printf("The DNS record memory is full.\n");
	for (j; j < i; j++)//�����Ѹշֺõ�TEMP��i���ٴ��и��IP��domain
	{
		char* ex1 = strtok(Temp[j], " ");
		char* ex2 = strtok(NULL, "\n");
		if (ex2 == NULL)
		{
			printf("The record is not in a correct format.\n");
		}
		else
		{
			if (debug_level >= 1)
				printf("precache: %s %s\n", ex1, ex2);
			if (head == NULL) createcache(ex1, ex2);
			else insert(ex1, ex2);
			cacheSize++;
		}
	}
	start = end;
	fclose(fp);
	printf("Load precache success.\n\n");
}
//��cache����url��Ӧip������ip��NOTFOUND
char* Find(char* URL)
{
	char* NUrl;
	NUrl = (char*)malloc(sizeof(char) * 210);
	strcpy(NUrl, URL);
	Translate* temp = head;
	while (temp->next)
	{
		if (strcmp(temp->domain, NUrl) == 0)//�ҵ�
		{
			return temp->IP;
			break;
		}
		temp = temp->next;
	}
	return NOTFOUND;//û�ҵ�
}
