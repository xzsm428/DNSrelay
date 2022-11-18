#pragma once
void read_pre_cache();//读取dnsrelay.txt
char* Find(char* URL);//从cache中找url对应ip，返回ip或NOTFOUND
void insert(char* ip, char* url);//将回答写入cache中
