#pragma once
void disp_head();//��ʼ����
void proc_args(int argc, char* argv[]);//�����ṩ�Ĳ������ô�ӡ������Ϣ����������ⲿdns��������ַ
void GetURL(char* buf); //��ȡDNS�е�����
unsigned short ReplaceNewID(unsigned short OldID, SOCKADDR_IN temp, BOOL ifdone);//������IDת��Ϊ�µ�ID��������Ϣд��IDת������
void standard_print(char* buf, int length);//��ӡ�յ���DNS���ĵľ�����Ϣ��debug_level >= 2��
