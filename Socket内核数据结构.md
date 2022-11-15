# Socket内核数据结构
```c
int __sys_socket(int family, int type, int protocol)
{
	struct socket *sock;
	int flags;
    // family 协议族 AF_INET ip 通信
    // type socket 类型 SOCK_STREAM  SOCK_DGRAM  SOCK_RAW ..... 
    //  protocol  IPPROTO_UDP  IPPROTO_ICMP IPPROTO_ICMP .....
	sock = __sys_socket_create(family, type, protocol);
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	flags = type & ~SOCK_TYPE_MASK;
	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));//返回一个文件描述符号
}
```