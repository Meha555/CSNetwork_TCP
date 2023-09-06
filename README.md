# 收发并解析TCP/IP协议栈中的数据包

## 介绍

- 实现监听主机上的网络适配器

- 使用选定的网络适配器收发数据报

- 截获并分析TCP/IP网络协议栈中的各层协议

最终，本项目实现的功能有：

- 获取主机上的所有适配器

- 监听某个网络适配器，可以指定过滤规则

- 截获并分析TCP/IP网络协议栈中的各层协议数据包（包括以太网MAC帧、ARP请求分组、IP数据报、TCP报文段、UDP报文段、ICMP报文段）

- 将统计信息和数据输出到文件

### 题目

项目2：发送和接收TCP数据包

(a) TCP数据包结构设计；

(b) TCP数据包发送和接收过程。

TCP是一种面向连接的、可靠的传输层协议。TCP协议工作在网络层IP协议的基础上。本项目的目的是设计一个发送和接收TCP数据包的程序，其功能是填充一个TCP数据包，发送给目的主机，并在目的主机接收此TCP数据包，将数据字段显示显示在标准输出上。

### 软件架构

- TcpSender下是发送方源码
- TcpReceiver下是接收方源码
- com-headers下是公用头文件和API


### 开发环境

- Visual Studio 2022
- Npcap 1.73
- Npcap 1.13 SDK

## 使用说明

自行安装和配置Npcap，Linux环境下libpcap不够完善，不过UNIX环境直接使用POSIX标准下的socket就行

## 参考

[1] [Npcap Development Tutorial | Npcap Reference Guide](https://npcap.com/guide/npcap-tutorial.html)

[2] [libpcap入门教程 | tenfy' blog](https://tenfy.cn/2018/12/01/libpcap-tutorial/)

[3] [[精品\]winpcap过滤器语法 - 道客巴巴 (doc88.com)](http://www.doc88.com/p-8466091442168.html)
