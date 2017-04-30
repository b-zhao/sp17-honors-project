//curl --socks5 localhost:1080 -u admin www.google.com
//netstat -tlnp
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


#include "Socks5.h"



#define USERNAME "admin"
#define PASSWORD "123"

int secret[8] = { 125,126,173,225,233,241,296,374 };

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
	*resp_ptr ++ = AUTH_CODE;
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
	if((strncmp(input_username, USERNAME, strlen(USERNAME)) == 0) &&
				(strncmp(input_password, PASSWORD, strlen(PASSWORD)) == 0)){
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
		*resp_ptr ++ = 0x01;
		send(client_sock, resp_buffer, 2, 0);

		close(client_sock);
		return SOCKS5_ERROR_AUTH;
	}
}




// parse command, and try to connect real server.
// return socket for success, -1 for failed.
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

	// get real server ip address
	if((unsigned)recv_buffer[3] == SOCKS5_IPV4) {

		memcpy(&target_server_addr.sin_addr.s_addr, recv_ptr + 4, 4);
		memcpy(&target_server_addr.sin_port, recv_ptr + 4 + 4, 2);

		fprintf(stderr, "target_server: %s %d\n", inet_ntoa(target_server_addr.sin_addr), ntohs(target_server_addr.sin_port));
	}
	else if((unsigned)recv_buffer[3] == SOCKS5_DOMAIN) {
		char domain_length[2] = {0};
		memcpy(domain_length, recv_ptr + 4, 1);
		//  = *(&conn_request -> address_type
		// 	           + sizeof(conn_request -> address_type));
		char target_domain[256] = {0};

 		strncpy(target_domain, recv_ptr + 5, (unsigned int)(domain_length[0]));

		fprintf(stderr, "target: %s\n", target_domain);

		 struct hostent *phost = gethostbyname(target_domain);
		 if(phost == NULL) {
			 //fprintf(stderr, "Resolve %s error!\n" , target_domain);
			close(client_sock);
			return SOCKS5_ERROR_TARGET;
		 }
		 memcpy(&target_server_addr.sin_addr , phost -> h_addr_list[0] , phost -> h_length);

		 memcpy(&target_server_addr.sin_port, recv_ptr + 5 + (unsigned int)(domain_length[0]), 2);
		 fprintf(stderr, "target_server: %s %d\n", inet_ntoa(target_server_addr.sin_addr), ntohs(target_server_addr.sin_port));

	}
	fprintf(stderr, "%s reached line %d in %s\n", __FILE__,__LINE__,__FUNCTION__);

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

	char buffer[BUFF_SIZE] = {0};

	int ret = 0;

	struct timeval time_out;
	time_out.tv_sec = 0;
	time_out.tv_usec = TIME_OUT;

	fd_set fd_read;

	while(1)  {
		FD_ZERO(&fd_read);
		FD_SET(client_sock, &fd_read);
		FD_SET(target_server_sock, &fd_read);
		int chosen = 0;

		if(client_sock > target_server_sock) {
			chosen = client_sock;
		}
		else {
			chosen = target_server_sock;
		}
		ret = select(chosen + 1, &fd_read, NULL, NULL, &time_out);

		if(ret == -1) {
			perror("select fail");
			break;
		}
		else if(ret == 0){
			perror("select time out");
			continue;
		}

		if(FD_ISSET(client_sock, &fd_read)){
			fprintf(stderr, "client can read!\n");
			bzero(buffer, BUFF_SIZE);
			ret = recv(client_sock, buffer, BUFF_SIZE, 0);
			if(ret > 0) {
		 		fprintf(stderr, "%s", buffer);
		 		fprintf(stderr, "recv %d bytes from client.\n", ret);
				ret = send(target_server_sock, buffer, ret, 0);
				if(ret == -1) {
					perror("send data to real server error");
					break;
				}
			 	fprintf(stderr, "send %d bytes to client!\n", ret);
		 	}
			else if(ret == 0){
				fprintf(stderr, "client close socket.\n");
				break;
			}
			else {
				perror("recv from client error");
				break;
			}
		}
		else if(FD_ISSET(target_server_sock, &fd_read)) {
			fprintf(stderr, "real server can read!\n");
			bzero(buffer, BUFF_SIZE);
			ret = recv(target_server_sock, buffer, BUFF_SIZE, 0);
			if(ret > 0) {
				fprintf(stderr, "%s", buffer);
				fprintf(stderr, "recv %d bytes from real server.\n", ret);
				ret = send(client_sock, buffer, ret, 0);
				if(ret == -1){
					perror("send data to client error");
					break;
				}
			}
			else if(ret == 0) {
				fprintf(stderr, "real server close socket.\n");
				break;
			}
			else {
				perror("recv from real server error");
				break;
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

int main(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "connect_to_remote proxy for test\n");
		fprintf(stderr, "Usage: %s <proxy_port>\n", argv[0]);
		return SOCKS5_ERROR_USAGE;
	}
	fprintf(stderr, "==============================\n\n\n");

	fprintf(stderr, "Welcome to connect_to_remote proxy server\n\n\n");

	fprintf(stderr, "==============================\n");
	int s, proxy_sock;


	struct addrinfo hints, *result, *rp;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, argv[1], &hints, &result);
	if (s != 0) {
	   fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
	   exit(1);
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
	        PRINTF(LEVEL_ERROR, "setsockopt SO_NOSIGPIPE fail.\n");
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