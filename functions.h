#pragma once
void disp_head();//开始界面
void proc_args(int argc, char* argv[]);//根据提供的参数设置打印调试信息级别和设置外部dns服务器地址
void GetURL(char* buf); //获取DNS中的域名
unsigned short ReplaceNewID(unsigned short OldID, SOCKADDR_IN temp, BOOL ifdone);//将请求ID转换为新的ID，并将信息写入ID转换表中
void standard_print(char* buf, int length);//打印收到的DNS报文的具体信息（debug_level >= 2）
