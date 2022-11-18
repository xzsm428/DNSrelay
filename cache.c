#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"definition.h"
extern int debug_level;
Translate* head, *start, *end;
int cacheSize = 0;
void createcache(char *ip,char* url)//头节点,创建链表 
{
	head = (struct Translate*)malloc(sizeof(struct Translate));
	head->next = NULL;
	head->prior = NULL;
	head->IP = ip;
	head->domain = url;
	end = head;
	cacheSize++;
}
void insert(char* ip, char* url)//插入 尾插法
{
	if (cacheSize < AMOUNT)//cache中还有空位，加到链表最后边
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
	else//cache中没空位 LRU 先删后插
	{
		struct Translate* temp = start->next;
		while (temp->next)
		{
			if (strcmp(temp->domain, url) == 0)//若该url之前已经被写入
				break;
			temp = temp->next;
		}
		if (temp->next == NULL)//url没被写入 删除后再加
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
		else//已有url，把它挪到后边去 
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
void read_pre_cache()//读取dnsrelay.txt
{
	int i = 0, j = 0;
	FILE* fp = fopen("dnsrelay.txt", "r");
	if (!fp)
	{
		printf("Open file failed.\n");
		exit(-1);
	}
	char* Temp[AMOUNT];
	while (i < AMOUNT - 1)//实现把每一行分开的操作
	{
		Temp[i] = (char*)malloc(sizeof(char) * 200);
		if (fgets(Temp[i], 1000, fp) == NULL)//如果错误或者读到结束符，就返回NULL；
			break;
		i++;
	}
	if (i == AMOUNT - 1)
		printf("The DNS record memory is full.\n");
	for (j; j < i; j++)//用来把刚分好的TEMP【i】再次切割成IP和domain
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
//从cache中找url对应ip，返回ip或NOTFOUND
char* Find(char* URL)
{
	char* NUrl;
	NUrl = (char*)malloc(sizeof(char) * 210);
	strcpy(NUrl, URL);
	Translate* temp = head;
	while (temp->next)
	{
		if (strcmp(temp->domain, NUrl) == 0)//找到
		{
			return temp->IP;
			break;
		}
		temp = temp->next;
	}
	return NOTFOUND;//没找到
}
