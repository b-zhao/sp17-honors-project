/* *
 *  CS296 Honor Project
 */
//curl --socks5 localhost:1080 -u admin www.google.com
//netstat -tlnp

#include "Socks5.h"

#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>



// macro
#define USERNAME "admin"
#define PASSWORD "123"
// encryption secret
int secret[8] = {125,126,173,225,233,241,296,374};


//encryption function
void encrypt(char* origin,size_t len,int * key,int key_len);


//network
int select_method(int client_sock);
int auth_client(int client_sock);
int ack_request(int client_sock);
int transfer_data(int client_sock, int target_server_sock);
int connect_to_remote(void *client_fd);



int main(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "connect_to_remote proxy for test\n");
		fprintf(stderr, "Usage: %s <proxy_port>\n", argv[0]);
		return SOCKS5_ERROR_USAGE;
	}
	fprintf(stderr, "==================================\n");
	fprintf(stderr, "|                                |\n");
	fprintf(stderr, "| Welcome to socks5 proxy server |\n");
	fprintf(stderr, "|                                |\n");
	fprintf(stderr, "==================================\n");

	int s, proxy_sock;


	struct addrinfo hints, *result, *rp;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, argv[1], &hints, &result);
	if (s != 0) {
	   fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
	   return SOCKS5_ERROR_GETADDRINFO;
	}


	for (rp = result; rp != NULL; rp = rp->ai_next) {
		proxy_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (proxy_sock == -1){
			continue;
		}
		if (bind(proxy_sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;                  /* Success */
		}
		else {
			perror("bind error");
			return SOCKS5_ERROR_BIND;
		}
		close(proxy_sock);
	}

	freeaddrinfo(result);

	if(proxy_sock < 0){
		perror("socket error");
		return SOCKS5_ERROR_SOCKET;
	}
	// setsockopt
	int optval = 1;
	setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval));
	// setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	#ifdef SO_NOSIGPIPE
	    if (-1 == setsockopt(proxy_sock, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval))) {
	        fprintf(stderr, "setsockopt SO_NOSIGPIPE fail.\n");
	        return -1;
	    }
	#endif
	if(listen(proxy_sock, MAX_USER) < 0) {
		perror("Listen error");
		return SOCKS5_ERROR_LISTEN;
	}

	struct sockaddr_in client_addr;
	int client_sock;
	int client_len = sizeof(struct sockaddr_in);
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);

	while((client_sock = accept(proxy_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_len))) {
		fprintf(stderr, "Connected from %s, processing......\n", inet_ntoa(client_addr.sin_addr));
		pthread_t tid;
		if(pthread_create(&tid, NULL, (void *)connect_to_remote, (void *)&client_sock)) {
			perror("Thread error...");
			close(client_sock);
		}
		else {
			pthread_detach(tid);
		}
	}
}



void encrypt(char* origin,size_t len,int * key,int key_len){
    int i;
    for(i = 0; i <len; i++){
        origin[i] = origin[i]^key[i%key_len];
    }
}

// Select auth method, return 0 if success, -1 if failed
int select_method(int client_sock) {
	// /*
	//  * server response
	//  */
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);
	char recv_buffer[BUFF_SIZE] = {0};
	char resp_buffer[2] = {0};
	char *recv_ptr = recv_buffer;
	char *resp_ptr = resp_buffer;


	int ret = recv(client_sock, recv_buffer, BUFF_SIZE, 0);
	if(ret <= 0) {
		perror("recv error");
		close(client_sock);

		return SOCKS5_ERROR_RECV;
	}
	fprintf(stderr,"select_method: recv %d bytes\n", ret);

	*resp_ptr ++ = SOCKS5_VERSION;
	// resp_ptr ++;

 	// if not socks5
	if((unsigned)recv_buffer[0] != SOCKS5_VERSION) {
		*resp_ptr ++ = 0xff;
		send(client_sock, resp_buffer, 2, 0);
		close(client_sock);

		return SOCKS5_ERROR_METHOD;
	}
	*resp_ptr ++ = AUTH_MODE;
	if(send(client_sock, resp_buffer, 2, 0) == -1) {
		close(client_sock);
		return SOCKS5_ERROR_SEND;
	}
	fprintf(stderr,"select_method done\n");

	return SOCKS5_SUCCESS;
}


// test password, return 0 for success.
int auth_client(int client_sock) {
	char recv_buffer[BUFF_SIZE] = {0};
	char resp_buffer[BUFF_SIZE] = {0};
	char *recv_ptr = recv_buffer;
	char *resp_ptr = resp_buffer;

	// /*
	//  *  authentication response
	//  */
	// auth username and password
	int ret = recv(client_sock, recv_buffer, BUFF_SIZE, 0);
	if(ret <= 0){
		perror("recv username and password error");
		close(client_sock);
		return SOCKS5_ERROR_RECV;
	}
	fprintf(stderr, "AuthPass: recv %d bytes\n", ret);


	*resp_ptr ++ = 0x01;

	char input_username[256] = {0};
	char input_password[256] = {0};

	char username_len[2] = {0};
	strncpy(username_len, recv_ptr + 1, 1);

	char password_len[2] = {0};
	strncpy(password_len, recv_ptr + 1 + 1 + (unsigned)username_len[0], 1);

	fprintf(stderr, "recv %zu byte from client = [%s]\n", strlen(resp_buffer), resp_buffer);

	strncpy(input_username, recv_ptr + 2, (unsigned int)(username_len[0]));
	strncpy(input_password, recv_ptr + 2 + (unsigned int)(username_len[0]) + 1, (unsigned int)(password_len[0]));
	fprintf(stderr, "parse username: %s\npassword: %s\n", input_username, input_password);
	// check username and password
	if((strcmp(input_username, USERNAME) == 0) &&
				(strcmp(input_password, PASSWORD) == 0)){
		*resp_ptr ++ = 0x00;
		if(send(client_sock, resp_buffer, 2, 0) == -1) {
			close(client_sock);
			return SOCKS5_ERROR_SEND;
		}
		else {
			fprintf(stderr, "AUTH success\n");

			return SOCKS5_SUCCESS;
		}
	}
	else {
		fprintf(stderr, "AUTH failed\n");
		*resp_ptr ++ = 0x01;
		send(client_sock, resp_buffer, 2, 0);
		close(client_sock);
		return SOCKS5_ERROR_AUTH;
	}
}




// parse command, and try to connect real server.
// return socket for success, error code for failed.
int ack_request(int client_sock) {
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);

	char recv_buffer[BUFF_SIZE] = {0};
	char resp_buffer[BUFF_SIZE] = {0};
	char *recv_ptr = recv_buffer;
	char *resp_ptr = resp_buffer;

	char input_password[256] = {0};
	//
	// recv command
	int ret = recv(client_sock, recv_buffer, BUFF_SIZE, 0);
	if(ret <= 0) {
		perror("recv connect command error");
		close(client_sock);
		return SOCKS5_ERROR_RECV;
	}


	if(((unsigned)recv_buffer[0] != SOCKS5_VERSION)
	|| ((unsigned)recv_buffer[1] != SOCKS5_CONNECT)
	|| ((unsigned)recv_buffer[3] == SOCKS5_IPV6)) {
	//fprintf(stderr, "connect command error.\n");
		close(client_sock);
		return SOCKS5_ERROR_ACKCMD;
	}

	// begin process connect request
	struct sockaddr_in target_server_addr;
	bzero(&target_server_addr, sizeof(struct sockaddr_in));

	target_server_addr.sin_family = AF_INET;

	// fd is my file descriptor

	// get real server ip address
	if((unsigned)recv_buffer[3] == SOCKS5_IPV4) {

		memcpy(&target_server_addr.sin_addr.s_addr, recv_ptr + 4, 4);
		memcpy(&target_server_addr.sin_port, recv_ptr + 4 + 4, 2);

	}
	else if((unsigned)recv_buffer[3] == SOCKS5_DOMAIN) {
		char domain_length[2] = {0};
		memcpy(domain_length, recv_ptr + 4, 1);

		char target_domain[256] = {0};

 		strncpy(target_domain, recv_ptr + 5, (unsigned int)(domain_length[0]));

		 struct hostent *phost = gethostbyname(target_domain);
		 if(phost == NULL) {
			 //fprintf(stderr, "Resolve %s error!\n" , target_domain);
			close(client_sock);
			return SOCKS5_ERROR_TARGET;
		 }

		 memcpy(&target_server_addr.sin_addr , phost -> h_addr_list[0] , phost -> h_length);
		 memcpy(&target_server_addr.sin_port, recv_ptr + 5 + (unsigned int)(domain_length[0]), 2);

	}
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);
	fprintf(stderr, "target_server: %s %d\n", inet_ntoa(target_server_addr.sin_addr), ntohs(target_server_addr.sin_port));

	// try to connect to real server
	int target_server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(target_server_sock < 0) {
		perror("Socket failed\n");

		close(client_sock);
		return SOCKS5_ERROR_SOCKET;
	}
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);




	// fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);

	ret = connect(target_server_sock, (struct sockaddr *)&target_server_addr, sizeof(struct sockaddr_in));
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);

	if(ret == 0) {
		// fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);
		*resp_ptr ++ = SOCKS5_VERSION;
		*resp_ptr ++ = 0x00;// success
		*resp_ptr ++ = 0x00;// reserve
		*resp_ptr ++ = 0x01;//addr type
		if(send(client_sock, resp_buffer, 10, 0) == -1) {
			close(client_sock);
			return SOCKS5_ERROR_SEND;
		}
	}
	else {
		perror("Connect to real server error");
		*resp_ptr ++ = SOCKS5_VERSION;
		*resp_ptr ++ = 0x01;// fail
		*resp_ptr ++ = 0x00;// reserve
		*resp_ptr ++ = 0x01;//addr type
		send(client_sock, resp_buffer, 10, 0);
		close(client_sock);
		return SOCKS5_ERROR_CONNECT;
	}
	fprintf(stderr, "Connect to remote server!\n");

	return target_server_sock;
}




int transfer_data(int client_sock, int target_server_sock) {
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);

	fd_set readfds;

	//register my fd
	FD_SET(target_server_sock, &readfds);
	char buffer[BUFF_SIZE] = {0};
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = TIME_OUT;

	int num_ready, ret, i;

	while(1)  {
		FD_ZERO(&readfds);
		int my_read_fds[2] = {client_sock, target_server_sock};
		int read_fd_count = 2;
		for (i = 0; i < read_fd_count; i++) {
			FD_SET(my_read_fds[i], &readfds);
		}
		num_ready = select(FD_SETSIZE, &readfds, NULL, NULL, &timeout);

		if(num_ready == -1) {
			perror("error in select()");
			break;
		}
		else if(num_ready == 0){
			perror("select time out");
			continue;
		}
		else {
			for (int i=0; i < read_fd_count; i++) {
				if (FD_ISSET(my_read_fds[i], &readfds) && my_read_fds[i] == client_sock) {
					bzero(buffer, BUFF_SIZE);
					ret = recv(my_read_fds[i], buffer, BUFF_SIZE, 0);
					if(ret < 0) {
						perror("recv from client error");
						return SOCKS5_ERROR_RECV_CLIENT;
					}
					else if(ret == 0) {
						fprintf(stderr, "client close socket.\n");
						break;
					}
					else {
				 		fprintf(stderr, "%s", buffer);
				 		fprintf(stderr, "recv %d bytes from client.\n", ret);
						ret = send(target_server_sock, buffer, ret, 0);
						if(ret == -1) {
							perror("send data to real server error");
							break;
						}
					 	fprintf(stderr, "send %d bytes to client!\n", ret);
				 	}
				}
				else if (FD_ISSET(my_read_fds[i], &readfds) && my_read_fds[i] == target_server_sock) {
					bzero(buffer, BUFF_SIZE);
					ret = recv(my_read_fds[i], buffer, BUFF_SIZE, 0);
					if(ret < 0){
						perror("recv from real server error");
						return SOCKS5_ERROR_RECV_SERVER;
					}
					else if(ret == 0) {
						fprintf(stderr, "real server close socket.\n");
						break;
					}
					else {
						fprintf(stderr, "%s", buffer);
						fprintf(stderr, "recv %d bytes from real server.\n", ret);
						ret = send(client_sock, buffer, ret, 0);
						if(ret == -1){
							perror("send data to client error");
							break;
						}
					}
				}

			}
		}

	}
	return SOCKS5_SUCCESS;
}





int connect_to_remote(void *client_fd) {
	int client_sock = *(int *)client_fd;

	if(select_method(client_sock) == -1) {
		perror("method");
		return SOCKS5_ERROR_METHOD;
	}

	if(auth_client(client_sock) == -1) {
		perror("authentication");

		return SOCKS5_ERROR_AUTH;
	}

	int target_server_sock = ack_request(client_sock);
	if(target_server_sock == -1) {
		perror("ack_request");
		return SOCKS5_ERROR_ACKCMD;
	}

	transfer_data(client_sock, target_server_sock);

	close(client_sock);
	close(target_server_sock);

	return SOCKS5_SUCCESS;
}
