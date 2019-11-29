#include "csapp.h"
/************************** 
 * Error-handling functions
 **************************/
void unix_error(char *msg)
{
	fprintf(stderr, "%s: %s\n",msg,strerror(errno));
	exit(0);
}

void dns_error(char *msg) /* DNS-style error */
{
    fprintf(stderr, "%s: DNS error %d\n", msg, h_errno);
    exit(0);
}
/*********************************************
 * Wrappers for Unix process control functions
 ********************************************/
pid_t Fork()
{
	pid_t pid = fork();

	if(pid < 0)
		unix_error("Fork error");
	return pid;
}

void Execve(const char *fileName, char *const argv[], char *const envp[])
{
	if(execve(fileName, argv, envp) < 0)
		unix_error("Execve error");
}

pid_t Wait(int *status)
{
	pid_t pid = wait(status);

	if(pid < 0)
		unix_error("Wait error");
	return pid;
}

/********************************
 * Wrappers for Unix I/O routines
 ********************************/
int Open (const char *pathName, int flag, mode_t mode)
{
	int fd = open(pathName, flag, mode);

	if(fd < 0)
		unix_error("Open error");
	return fd;
}

ssize_t Read(int fd, void *buf, size_t count)
{
	ssize_t rc = read(fd, buf, count);

	if(rc < 0)
		unix_error("Read error");
	return rc;
}

ssize_t Write(int fd, const void *buf, size_t count)
{
	ssize_t rc = write(fd, buf, count);

	if(rc < 0)
		unix_error("Write error");
	return rc;
}

void Close(int fd)
{
	int rc = close(fd);
	if(rc < 0)
		unix_error("Close error");
}

int Dup2(int fd1, int fd2)
{
	int rc = dup2(fd1, fd2);
	if (rc < 0)
		unix_error("Dup2 error");
	return rc;
}

/*********************************************************************
 * The Rio package - robust I/O functions
 **********************************************************************/
ssize_t rio_readn(int fd, void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nread;
	char *bufptr = usrbuf;

	while(nleft > 0){
		if((nread = Read(fd, bufptr, nleft)) < 0){
			if(errno == EINTR)
				nread = 0;
			else
				return -1;
		}
		else if(nread == 0)
			break;
		nleft -= nread;
		bufptr += nread;
	}
	return (n-nleft);
}

ssize_t rio_writen(int fd, void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nwritten;
	char *bufptr = usrbuf;

	while(nleft > 0){
		if((nwritten = Write(fd, usrbuf, n)) <= 0){
			if(errno == EINTR)
				nwritten = 0;
			else
				return -1;
		}
		nleft -= nwritten;
		bufptr += nwritten;
	}
	return n;
}

void rio_readinitb(rio_t *rp, int fd)
{
	rp->rio_fd = fd;
	rp->rio_cnt = 0;
	rp->rio_bufptr = rp->rio_buf;
}

static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n)
{
	while(rp->rio_cnt <= 0){
		rp->rio_cnt = Read(rp->rio_fd, rp->rio_buf, sizeof(rp->rio_buf));
		if(rp->rio_cnt < 0){
			if(errno != EINTR)
				return -1;
		}
		else if(rp->rio_cnt == 0)
			return 0;
		else
			rp->rio_bufptr = rp->rio_buf;
	}
	int cnt = rp->rio_cnt < n ? rp->rio_cnt : n;
	memcpy(usrbuf, rp->rio_bufptr, cnt);
	rp->rio_bufptr += cnt;
	rp->rio_cnt -= cnt;
	return cnt;
}

ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen)
{
	int n, rc;
	char c, *bufptr = usrbuf;

	for (n = 1; n < maxlen; n++) {
		if ((rc = rio_read(rp, &c, 1)) == 1) {
			*bufptr++ = c;
			if(c == '\n') {
				n++;
				break;
			}
		} 	else if (rc == 0) {
				if(n == 1)
					return 0;
				else
					break;
		} 	else	return -1;
	}
	*bufptr = 0;
	return n-1;
}

ssize_t rio_readnb(rio_t *rp, void *usrbuf, size_t n){
	size_t nleft = n;
	ssize_t nread;
	char *bufptr = usrbuf;

	while (nleft > 0) {
		if ((nread = rio_read(rp, &bufptr, nleft)) < 0)
			return -1;
		else if (nread == 0)
			break;
		nleft -= nread;
		bufptr += nread;
	}
	return (n - nleft);
}

/**********************************
 * Wrappers for robust I/O routines
 **********************************/
 ssize_t Rio_readn(int fd, void *ptr, size_t nbytes)
 {
 	ssize_t n = rio_readn(fd, ptr, nbytes);
 	if (n < 0) 
 		unix_error("Rio_readn error");
 	return n;
 }

 void Rio_writen(int fd, void *usrbuf, size_t n)
 {
 	if (rio_writen(fd, usrbuf, n) != n)
 		unix_error("Rio_writen error");
 }

 void Rio_readinitb(rio_t *rp, int fd)
 {
 	rio_readinitb(rp, fd);
 }

 ssize_t Rio_readnb(rio_t *rp, void *usrbuf, size_t n)
 {
 	ssize_t rc = rio_readnb(rp, usrbuf, n);
 	if (rc < 0)
 		unix_error("Rio_readnb error");
 	return rc;
 }

 ssize_t Rio_readlineb(rio_t *rp, void *usrbuf, size_t n)
 {
 	ssize_t rc = rio_readlineb(rp, usrbuf, n);
 	if(rc < 0)
 		unix_error("Rio_readlineb error");
 	return rc;
 }

 /**************************** 
 * Sockets interface wrappers
 ****************************/
 int Socket(int domain, int type, int protocol)
 {
 	int sd = socket(domain, type, protocol);
 	if(sd < 0)
 		unix_error("Socket error");
 	return sd;
 }

 void Setsockopt(int s, int level, int optname, const void *optval, int optlen)
 {
 	int rc = setsockopt(s, level, optname, optval, optlen);
 	if(rc < 0)
 		unix_error("Setsockopt error");
 }

 void Connect(int sockfd, struct sockaddr *serv_addr, int addrlen)
 {
 	int rc = connect(sockfd, serv_addr, addrlen);
 	if(rc < 0)
 		unix_error("Connect error");
 }

void Bind(int sockfd, struct sockaddr *my_addr, int addrlen)
{
	int rc = bind(sockfd, my_addr, addrlen);
	if(rc < 0)
		unix_error("Bind error");
}

void Listen(int s, int backlog)
{
	int rc = listen(s, backlog);
	if(rc < 0)
		unix_error("Listen error");
}

int Accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	int connfd = accept(s, addr, addrlen);
	if(connfd < 0)
		unix_error("Accept error");
	return connfd;
}

/************************
 * DNS interface wrappers 
 ***********************/

 int Getaddrinfo(const char *host, int port, 
 				 const struct addrinfo *hints, struct addrinfo **result)
 {
 	char service[32];
 	sprintf(service, "%d", port);
 	int rc = getaddrinfo(host, service, hints, result);
 	if(rc < 0)
 		unix_error("Getaddrinfo error");
 	return rc;
 }

 void Freeaddrinfo(struct addrinfo *result)
 {
 	freeaddrinfo(result);
 }

 int Getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, 
 				 char *port, size_t portlen, int flag)
 {
 	int rc = getnameinfo(sa, salen, host, hostlen, port, portlen, flag);
 	if(rc < 0)
 		unix_error("Getnameinfo error");
 	return rc;
 }

/******************************** 
 * Client/server helper functions
 ********************************/

 int open_clientfd(char *hostname, int port)
 {
 	int clientfd;
 	struct addrinfo hints, *listp, *p;

 	memset(&hints, 0, sizeof(struct addrinfo));
 	hints.ai_socktype = SOCK_STREAM;
 	hints.ai_flags = AI_NUMERICSERV;
 	hints.ai_flags |= AI_ADDRCONFIG;
 	Getaddrinfo(hostname, port, &hints, &listp);

 	for(p = listp; p; p = p->ai_next){
 		if((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
 			continue;
 		if(connect(clientfd, p->ai_addr, p->ai_addrlen) != -1)
 			break;
 		Close(clientfd);
 	}

 	Freeaddrinfo(listp);
 	if(!p)
 		return -1;
 	else
 		return clientfd;
 }

 int open_listenfd(int port)
 {
 	struct addrinfo hints, *listp, *p;
 	int listenfd, optval=1;

 	memset(&hints, 0, sizeof(struct addrinfo));
 	hints.ai_socktype = SOCK_STREAM;
 	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
 	Getaddrinfo(NULL, port, &hints, &listp);

 	for(p = listp; p; p = p->ai_next){
 		if((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
 			continue;

 		Setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

 		if(bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
 			break;
 		Close(listenfd);
 	}

 	Freeaddrinfo(listp);
 	if(!p)
 		return -1;
 	if(listen(listenfd, LISTENQ) < 0){
 		Close(listenfd);
 		return -1;
 	}
 	return listenfd;
 }

 /***************************************
 * Wrappers for memory mapping functions
 ***************************************/
void *Mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) 
{
    void *ptr;

    if ((ptr = mmap(addr, len, prot, flags, fd, offset)) == ((void *) -1))
	unix_error("mmap error");
    return(ptr);
}

void Munmap(void *start, size_t length) 
{
    if (munmap(start, length) < 0)
	unix_error("munmap error");
}

/******************************************
 * Wrappers for the client/server helper routines 
 ******************************************/
int Open_clientfd(char *hostname, int port) 
{
    int rc;

    if ((rc = open_clientfd(hostname, port)) < 0) {
	if (rc == -1)
	    unix_error("Open_clientfd Unix error");
	else        
	    dns_error("Open_clientfd DNS error");
    }
    return rc;
}

int Open_listenfd(int port) 
{
    int rc;

    if ((rc = open_listenfd(port)) < 0)
	unix_error("Open_listenfd error");
    return rc;
}
/* $end csapp.c */
