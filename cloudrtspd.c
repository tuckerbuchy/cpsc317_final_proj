#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <cv.h>
#include <highgui.h>
#include "cloud_helper.h"
#include "rtspd.h"
#include <unistd.h>

#define RTP_VERSION_2 2
#define JPEG_PAYLOAD_TYPE 26
#define DOLLAR_SIGN 0x24

#define MAX_MESSAGE_LENGTH 400
#define MAX_WORD_LENGTH 64

#define COULD_NOT_OPEN_ERROR_CODE 424
#define BACKLOG 10	 // how many pending connections queue will hold

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*) sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

typedef struct {
	char* command;
	char* file_path;
	int seq;
	int session_id;
	int scale;
} RTSPmsg;

typedef struct PlaybackTimer{
	struct sigevent play_event;
	timer_t play_timer;
	struct itimerspec play_interval;
} PlaybackTimer;

typedef struct OpenCloudConnection{
	char* host;
	int port;
	int socket_fd;
	struct OpenCloudConnection* next_connection;
} OpenCloudConnection;

typedef struct {
	int socket;
	int session_id;
	int current_state;
	OpenCloudConnection* connections_list;
	pthread_mutex_t clientLock;
	char *current_file_path;
	uint16_t rtp_seq;
	int scale;
	PlaybackTimer* playback_timer;
	int current_frame_index;
} RTSPClient;

void pausePlayback(PlaybackTimer* playbackTimer);
void startPlayback(RTSPClient* clientInfo);
void sendFrameToClient(RTSPClient *clientInfo, char* frame_data, uint32_t frame_size);

int parseRTSPRequest(char* buffer, int bufLen, RTSPmsg* msg) {
	char toParse[bufLen];
	char* saved;
	char* savedLines;
	strcpy(toParse, buffer);
	//init RTSPmsg fields
	msg->seq = 0;
	msg->session_id = 0;
	msg->scale = 0;

	int i = 0;
	char* line = strtok_r(toParse, "\n", &savedLines);
	while (line) {
		char* word = strtok_r(line, " ", &saved);
		while (word != NULL) {
			char* wordBuf = (char*) calloc(MAX_WORD_LENGTH, sizeof(char));
			if (wordBuf == NULL)
			{
				printf("There wasn't enough memory to read the request.\n");
				return -1;
			}
			strcpy(wordBuf, word);
			//the first 2 tokens will contain nothing but the command and file sent from the client
			switch (i) {
				case (0):
					msg->command = wordBuf;
					break;
				case (1):
					msg->file_path = wordBuf;
					break;
			}

			if (strcmp(word, "CSeq:") == 0)
			{
				word = strtok_r(NULL, " ", &saved);
				wordBuf = (char*) calloc(MAX_WORD_LENGTH, sizeof(char));
				strcpy(wordBuf, word);
				msg->seq = atoi(wordBuf);
				i++;
			}
			else if (strcmp(word, "Scale:") == 0)
			{
				word = strtok_r(NULL, " ", &saved);
				wordBuf = (char*) calloc(MAX_WORD_LENGTH, sizeof(char));
				strcpy(wordBuf, word);
				msg->scale = atoi(wordBuf);
				i++;
			}
			else if (strcmp(word, "Session:") == 0)
			{
				word = strtok_r(NULL, " ", &saved);
				wordBuf = (char*) calloc(MAX_WORD_LENGTH, sizeof(char));
				strcpy(wordBuf, word);
				msg->session_id = atoi(wordBuf);
				i++;
			}
			word = strtok_r(NULL, " ", &saved);
			i++;
		}
		line = strtok_r(NULL, "\n", &savedLines);
	}
	return 0;
}

int recvRTSPRequest(RTSPClient* clientInfo, RTSPmsg* msg, char* buf, int bufLen) {
	int offset = 0;
	int socket = clientInfo->socket;
	int numRead = 0;

	while ((numRead = recv(socket, buf + offset, bufLen - offset, 0)) > 0) {
		if (numRead < 0) {
			fprintf(stderr, "ERROR ON CLIENT SOCKET\n");
			return -2;
		} else {
			offset += numRead;
			if (offset == bufLen) {
				bufLen += 1024;
				buf = realloc(buf, bufLen);
			}
			if (memcmp(buf + offset - 4, "\r\n\r\n", 4)) {
				printf("####Received####\n%s\n", buf);
				parseRTSPRequest(buf,bufLen, msg);
				return 0;
			}
		}
	}
	return -2;
}

int generateSessionId() {
	unsigned int r = (rand() % 99998) + 1;
	return r;
}

void sendMessage(int socketfd, char* message) {
	if (send(socketfd, message, strlen(message), 0) == -1)
		perror("send");
}

void sendSuccessResponse(int socketfd, int seq, int session_id){
	char* formattedMessage = "RTSP/1.0 200 OK\r\nCSeq: %d\r\nSession: %d\r\n\r\n";
	char message[MAX_MESSAGE_LENGTH];
	sprintf(message, formattedMessage, seq, session_id);
	printf("Sending success: %s\n", message);
	sendMessage(socketfd, message);
}

void sendFailureResponse(int socketfd, int errorCode, char* errorMsg, int seq)
{
	char* formattedMessage = "RTSP/1.0 %d \nCSeq: %d\r\n%s\r\n\r\n";
	char message[MAX_MESSAGE_LENGTH];
	sprintf(message, formattedMessage, errorCode, seq, errorMsg);
	printf("Sending error: %s\n", message);
	sendMessage(socketfd, message);
}


void processSetup(RTSPClient *clientInfo, RTSPmsg msg)
{
	if (clientInfo->session_id)
	{
		pausePlayback(clientInfo->playback_timer);
	}
	if (clientInfo->current_file_path)
	{
		free(clientInfo->current_file_path);
	}
	int path_length = strlen(msg.file_path + 8);
	clientInfo->current_file_path = (char* ) calloc(path_length, sizeof(char));
	strcpy(clientInfo->current_file_path, msg.file_path + 8);
	clientInfo->current_frame_index = 0;
	if (!clientInfo->session_id)
	{
		int session_id = generateSessionId();
		clientInfo->session_id = session_id;
	}
	msg.session_id = clientInfo->session_id;
	sendSuccessResponse(clientInfo->socket, msg.seq, msg.session_id);
}

void queryCloudForFrame(union sigval sv_data)
{
	RTSPClient *clientInfo = (RTSPClient*) sv_data.sival_ptr;

	pthread_mutex_lock(&clientInfo->clientLock);

	const struct cloud_server* cloud = get_cloud_server(clientInfo->current_file_path, clientInfo->current_frame_index);
	if (cloud == 0)
	{
		return;
	}
	int file_path_length = strlen(clientInfo->current_file_path);

	char ascii_buffer[64];
	sprintf(ascii_buffer, "%d", clientInfo->current_frame_index);
	printf("Current frame index : %s\n", ascii_buffer);

	int request_length = strlen(clientInfo->current_file_path) + sizeof(char) + strlen(ascii_buffer) + sizeof(char);
	char server_request[request_length];
	strcpy(server_request, clientInfo->current_file_path);
	server_request[file_path_length] = ':';

	strcpy(&server_request[file_path_length + sizeof(char)], ascii_buffer);
	server_request[file_path_length + sizeof(char) + strlen(ascii_buffer)] = '\n';

	int cloud_socket;
	printf("got here");
	OpenCloudConnection* root = clientInfo->connections_list;
	int found = 0;
	//check if we have an open connection
	if (root != 0)
	{
		while (root->next_connection != 0)
		{
			if (strcmp(root->host, cloud->server) == 0 && root->port == cloud->port)
			{
				found = 1;
				cloud_socket = root->socket_fd;
				break;
			}
			root = root->next_connection;
		}
	}
	if (found == 0)
	{
		struct addrinfo hints, *res;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		char port_c[20];
		sprintf(port_c, "%d", cloud->port);
		getaddrinfo(cloud->server, port_c, &hints, &res);

		// make a socket:
		cloud_socket = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol);

		if (cloud_socket == -1) {
			printf("Error is making socket to cloud\n");
			exit(1);
		}
		int rv = connect(cloud_socket, res->ai_addr, res->ai_addrlen);

		if (rv == -1) {
			printf("Error is making socket to cloud\n");
			exit(1);
		}
		root = (OpenCloudConnection*) malloc(sizeof(OpenCloudConnection));
		root->host = (char*) calloc(strlen(cloud->server), sizeof(char));
		strcpy(root->host, cloud->server);
		root->port = cloud->port;
		root->socket_fd =  cloud_socket;
	}

	if (send(cloud_socket, server_request, request_length, 0) <= 0)
	{
		printf("Error in sending to cloud\n");
	}

	int numRead = 0;
	char size_of_payload[5];

	numRead = recv(cloud_socket, &size_of_payload, 5, 0);

	printf("Read in %d bytes.\n", numRead);
	if (numRead == 5)
	{
		printf("Read correct number of bytes for the size. \n");
	}

	uint32_t size_of_payload_i = atoi(size_of_payload);
	printf("size of payload : %d\n", size_of_payload_i);

	int offset = 0;
	numRead = 0;
	char payload_buffer[size_of_payload_i];
	while ((numRead = recv(cloud_socket, &payload_buffer[offset], size_of_payload_i - offset, 0)) > 0)
	{
		printf("number of bytes read %d\n", numRead);
		if (numRead < 0) {
			fprintf(stderr, "ERROR ON CLIENT SOCKET\n");
			//todo: do this properly
			exit(1);
		}
		else
		{
			offset += numRead;
			printf("total bytes read in : %d\n", offset);
			if (offset == size_of_payload_i) {
				printf("Received full frame.\n");
				sendFrameToClient(clientInfo, payload_buffer, size_of_payload_i);
				break;
			}
		}
	}

	int scale = clientInfo->scale;
	int new_current_frame = clientInfo->current_frame_index + scale;
	if (new_current_frame >= 0) {
		printf("Updating the frame index \n");
		clientInfo->current_frame_index = new_current_frame;
		clientInfo->rtp_seq++;
	} else {
		printf("Setting frame index to 0 \n");
		clientInfo->current_frame_index = 0;
	}
	pthread_mutex_unlock(&clientInfo->clientLock);
}

//0                   1                   2                   3
//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|V=2|P|X|  CC   |M|     PT      |       sequence number         |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                           timestamp                           |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|           synchronization source (SSRC) identifier            |
//+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//|            contributing source (CSRC) identifiers             |
//|                             ....                              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
void sendFrameToClient(RTSPClient *clientInfo, char* frame_data, uint32_t frame_size)
{
	char dollar_sign = DOLLAR_SIGN;
	char channel = 0;

	uint8_t rtp_version_byte = 2 << 6;
	uint8_t payload_type = JPEG_PAYLOAD_TYPE;

	uint32_t timestamp = 0;
	uint32_t ssrc = 0;
	printf("client rtp sequence number : %d", clientInfo->rtp_seq);

	uint16_t packet_size = 12 + frame_size;

	char payload_buffer[frame_size];
	memcpy(&payload_buffer, frame_data, frame_size);
	printf("packet_size minus prefix: %d\n", packet_size);

	char packet_buffer[4 + packet_size];
	memset(&packet_buffer, 0, sizeof(packet_buffer));
	packet_buffer[0] = dollar_sign;
	packet_buffer[1] = channel;
	uint16_t packet_size_c = htons(packet_size);
	memcpy(&packet_buffer[2], &packet_size_c, 2);
	packet_buffer[4] = rtp_version_byte;
	packet_buffer[5] = payload_type;
	uint16_t rtp_seq_c = htons(clientInfo->rtp_seq);
	memcpy(&packet_buffer[6], &rtp_seq_c, 2);
	uint32_t timestamp_c = htonl(timestamp);
	memcpy(&packet_buffer[8], &timestamp_c, 4);
	uint32_t ssrc_c = htonl(ssrc);
	memcpy(&packet_buffer[12], &ssrc_c, 4);
	memcpy(&packet_buffer[16], &payload_buffer, frame_size);

	int total = 0;
	int bytes_left = sizeof(packet_buffer);
	int n;
	while (total < sizeof(packet_buffer)) {
		n = send(clientInfo->socket, packet_buffer + total, bytes_left, 0);
		if (n == -1) {
			break;
		}
		total += n;
		bytes_left -= n;
	}
}

void startPlayback(RTSPClient* clientInfo)
{
	PlaybackTimer* playbackTimer = clientInfo->playback_timer;
	if (!playbackTimer->play_interval.it_interval.tv_nsec)
	{
		memset(&playbackTimer->play_event, 0, sizeof(playbackTimer->play_event));
		playbackTimer->play_event.sigev_notify = SIGEV_THREAD;
		playbackTimer->play_event.sigev_value.sival_ptr = clientInfo;
		playbackTimer->play_event.sigev_notify_function = queryCloudForFrame;
		playbackTimer->play_interval.it_interval.tv_sec = 0;
		playbackTimer->play_interval.it_interval.tv_nsec = 40 * 1000000; // 40 ms in ns
		playbackTimer->play_interval.it_value.tv_sec = 0;
		playbackTimer->play_interval.it_value.tv_nsec = 1; // can't be zero

		timer_create(CLOCK_REALTIME, &playbackTimer->play_event, &playbackTimer->play_timer);
		timer_settime(playbackTimer->play_timer, 0, &playbackTimer->play_interval, NULL);
	}
}

void pausePlayback(PlaybackTimer* playbackTimer)
{
	playbackTimer->play_interval.it_interval.tv_sec = 0;
	playbackTimer->play_interval.it_interval.tv_nsec = 0;
	playbackTimer->play_interval.it_value.tv_sec = 0;
	playbackTimer->play_interval.it_value.tv_nsec = 0;
	timer_settime(playbackTimer->play_timer, 0, &playbackTimer->play_interval, NULL);
}

void processPlay(RTSPClient *clientInfo, RTSPmsg msg)
{
	sendSuccessResponse(clientInfo->socket, msg.seq, msg.session_id);
	clientInfo->scale = msg.scale;
	startPlayback(clientInfo);
}

void processPause(RTSPClient *clientInfo, RTSPmsg msg){

	sendSuccessResponse(clientInfo->socket, msg.seq, msg.session_id);
	pausePlayback(clientInfo->playback_timer);
}

void processTeardown(RTSPClient *clientInfo, RTSPmsg msg) {

//	//pause
	printf("teardown1\n");
	pausePlayback(clientInfo->playback_timer);
	//set video to NULL if it's been allocated
	clientInfo->session_id = 0;	
	sendSuccessResponse(clientInfo->socket, msg.seq, msg.session_id);
	printf("teardown6\n");
}

int verifySession(int clientSession, int msgSession)
{
	if (clientSession != msgSession || clientSession == 0)
	{
		return -1;
	}
	return 0;
}

void respToRTSPRequest(RTSPClient *clientInfo, RTSPmsg msg) {
	printf("locking...\n");
	pthread_mutex_lock(&clientInfo->clientLock);
	printf("locked...\n");
	if (strcmp(msg.command, "SETUP") == 0)
	{
		processSetup(clientInfo, msg);
	}
	else if (verifySession(clientInfo->session_id, msg.session_id) == 0)
	{
		if (strcmp(msg.command, "PLAY") == 0)
		{
			processPlay(clientInfo, msg);
		}
		else if (strcmp(msg.command, "PAUSE") == 0)
		{
			processPause(clientInfo, msg);
		}
		else if (strcmp(msg.command, "TEARDOWN") == 0)
		{
			processTeardown(clientInfo, msg);
		}
		else
		{
			printf("%s is not implemented! \n", msg.command);
		}
	}
	else
	{
		sendFailureResponse(clientInfo->socket, 454, "Invalid command, no session set up.", msg.seq);
	}
	pthread_mutex_unlock(&clientInfo->clientLock);
	printf("unlocked...\n");
}

void *handleClientConnection(void *clientData) {
	RTSPClient* clientInfo = (RTSPClient*) clientData;
	while (1) {
		RTSPmsg msg;
		char* buf = (char*) calloc(1024, sizeof(char));
		if (recvRTSPRequest(clientInfo, &msg, buf, 1024) != 0) {
			printf("Client connection failed \n");
			pausePlayback(clientInfo->playback_timer);
			free(buf);
			break;
		}
		else
		{
			printf("successfully received\n");
			respToRTSPRequest(clientInfo, msg);
			free(buf);
		}
	}
	close(clientInfo->socket);
	free(clientInfo->playback_timer);
	pthread_mutex_destroy(&clientInfo->clientLock);
	//cvReleaseCapture(&clientInfo->video);
	free(clientInfo);
	return NULL;
}

int initServer(RTSPServer *server) {

	struct addrinfo hints, *servinfo, *p;
	int yes = 1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP
	int rv;
	if ((rv = getaddrinfo(NULL, server->port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	// loop through all the results and bind to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((server->sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}
		if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}
		if (bind(server->sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(server->sockfd);
			perror("server: bind");
			continue;
		}
		break;
	}
	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		return -2;
	}
	freeaddrinfo(servinfo); // all done with this structure
	if (listen(server->sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}
	printf("server: waiting for connections...\n");

	return 0;
}


int waitForConnections(RTSPServer *server) {
	pthread_t thread; // Thread to be created
	struct sockaddr_storage their_addr; // connector's address information
	int new_fd;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];
	RTSPClient *clientInfo;
	while (1) {
		sin_size = sizeof their_addr;
		new_fd = accept(server->sockfd, (struct sockaddr *) &their_addr,
				&sin_size);

		if (new_fd == -1) {
			printf("Got bad socket fd in wait for connections");
			continue;
		}
		inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *) &their_addr), s, sizeof s);

		printf("server: got connection from %s\n", s);

		clientInfo = (RTSPClient*) malloc(sizeof(RTSPClient));
		clientInfo->connections_list = (OpenCloudConnection*) malloc(sizeof(OpenCloudConnection));
		clientInfo->connections_list->host = (char*) malloc(sizeof(char));
		pthread_mutex_init(&clientInfo->clientLock, NULL);
		clientInfo->playback_timer = (PlaybackTimer*) malloc(sizeof(PlaybackTimer));
		if (!clientInfo)
		{
			printf("There wasn't enough memory to fufill the connection.\n");
			continue;
		}
		clientInfo->socket = new_fd;
		pthread_create(&thread, NULL, handleClientConnection,
				(void *) clientInfo);
		printf("Starting thread...\n");
		pthread_detach(thread);
	}
	return 0;
}

