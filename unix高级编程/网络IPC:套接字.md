# 网络IPC:套接字
## 套接字描述符
### socket
```c
#include <sys/types.h> 
#include <sys/socket.h>
int socket(int domain, int type, int protocol);
error:-1
success:文件描述符号

domain:AF_*
AF_INET:ipv4
例如:
type:SOCK_*
SOCK_DGRAM
    无连接 不可靠传输(UDP)
SOCK_STREAM
    可靠传输(TCP)
SOCK_RAW
    IP协议(网络层)
    需要有超级用户权限,在网络层之上在创建一个自定义协议
protocol:
    当 type 可以指定多个协议的是够 可以使用protocol
    通常是0 默认协议
    SOCK_DGRAM UDP
    SOCK_STREAM TCP
``` 
### shutdown
```c
// 禁止接收和发送业务
#include <sys/socket.h>
int shutdown(int socket, int how);

how:
SHUT_RD
SHUT_WR
SHUT_RDWR
```
## 寻址
### 字节序
```c
字节序由处理器确定
TCP/IP 协议指定使用大端字节序

字节序转换函数
#include <arpa/inet.h>

uint32_t htonl(uint32_t hostlong)
    网络字节序表示32位
uint16_t htons(uint16_t hostshort)
    网络字节序表示16位
uint32_t ntohl(uint32_t netlong)
    主机字节序表示32位
uint16_t ntohs(uint16_t netshort);
    主机字节序表示16位

h:主机
n:网咯
l:4byte
s:2byte
```
### 地址格式
```c

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
}

sockaddr:可以额外添加成员,并且定义sa_data的大小


ipv4:
netinte/in.h
struct in_addr
  {
    in_addr_t s_addr;
  };
struct sockaddr_in
  {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;			/* Port number.  */
    struct in_addr sin_addr;		/* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
			   __SOCKADDR_COMMON_SIZE -
			   sizeof (in_port_t) -
			   sizeof (struct in_addr)];//全部为0
  };



// 将地址转换为人能理解的地址
#include <arpa/inet.h>
const char *inet_ntop(int af, const void *src,char *dst, socklen_t size);
将网络字节序转换wield二进制文本字符串
af:AF_INET   AF_INET6
size:dst缓存区大小
    INET_ADDRSTRLEN ipv6足够大的空间
    INET6_ADDRSTRLEN ipv4
#include <arpa/inet.h>
int inet_pton(int af, const char *src, void *dst);
    需要一个足够大的dst空间存发给 
    AF_INET6 128 bit 地址空间
    AF_INET 32 位地址空间
```

### 地址查询
```c
/etc/hosts  /etc/services DNS 存放网络配置信息

 #include <netdb.h>
extern int h_errno

void sethostent(int stayopen)

void herror(const char *s)
const char *hstrerror(int err)
/* System V/POSIX extension */
struct hostent *gethostent(void)
    主机数据库没有打开 会打开 
void endhostent(void)
     关闭主机数据库文件 

//过时 susv4 已经删除
struct hostent *gethostbyname(const char *name)
#include <sys/socket.h>       /* for AF_INET */
struct hostent *gethostbyaddr(const void *addr,
                              socklen_t len, int type)

返回采用网络字节序

// 对前面的替代
struct netent *getnetbyname(const char *name)
struct netent *getnetbyaddr(uint32_t net, int type);
struct netent *getnetent(void);
struct netent *getnetbyname(const char *name);
struct netent *getnetbyaddr(uint32_t net, int type);
void setnetent(int stayopen);
void endnetent(void);

返回采用网络字节序

/* GNU extensions */
struct hostent *gethostbyname2(const char *name, int af);



// 协议名和协议编号进行映射
#include <netdb.h>

struct protoent *getprotoent(void);

struct protoent *getprotobyname(const char *name);

struct protoent *getprotobynumber(int proto);

void setprotoent(int stayopen);

void endprotoent(void);


服务是地址端口表示的 每个服务由端口号来支持..

```
### 套接字和地址关联
```
bind() //port addr绑定

int getsockname();获取绑定套接字的地址
   -1 错误

clientfd 获取 client sock addr
int getpeername(clientfd,);
```
## 建立连接
```
int connect() 客户端

listen(fd,backblog)
    backlog tcp 默认 128
        等待连接并未完成三次握手的sock的队列

int accept(fd,addr,len);
获取三次握手成功队列的连接
addr len null 不会返回 客户端地址

accept() return -1 errono EAGAIN | EWOULDBLOCK 非阻塞返回 
accetp() 同步 等待到有socket 
```
## 数据传送
```c
read() write()

#include <sys/types.h>
#include <sys/socket.h>

ssize_t send(int sockfd, const void *buf, size_t len, inflags)
    buf len 于write一致
    inflags:

ssize_t sendto(int sockfd, const void *buf, size_t len, inflags,
               const struct sockaddr *dest_addr, socklen_addrlen)
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

```
## 套接字选项
```c
1.sock 类型的选项
2.层次管理选项(对下层协议支持)
3.特定协议选项

 #include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen);


```