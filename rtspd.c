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

typedef struct {
	int socket;
	int session_id;
	int current_state;
	int index_to_connections;
	pthread_mutex_t clientLock;
	uint16_t rtp_seq;
	int scale;
	PlaybackTimer* playback_timer;
	CvCapture* video;
	int current_frame_index;
} RTSPClient;

//this is where we maintain client connections

void pausePlayback(PlaybackTimer* playbackTimer);

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

void openVideo(RTSPClient* clientInfo, char* file_path)
{
	printf("video is being created...\n");
	// Open the video file.
	if (clientInfo->video == NULL)
	{
		clientInfo->video = cvCreateFileCapture(file_path);
	}
	else
	{
		clientInfo->video = cvCaptureFromFile(file_path);
	}
	printf("video is created...\n");
	if (!clientInfo->video) {
		printf("could not open video %s\n", file_path);
	}
	else
	{
		clientInfo->rtp_seq = 0;
		clientInfo->current_frame_index = 0;
		cvSetCaptureProperty(clientInfo->video, CV_CAP_PROP_POS_FRAMES, clientInfo->current_frame_index);
	}
}


void processSetup(RTSPClient *clientInfo, RTSPmsg msg)
{
	if (clientInfo->session_id)
	{
		pausePlayback(clientInfo->playback_timer);
	}
	openVideo(clientInfo, msg.file_path);
	if (clientInfo->video)
	{
		if (!clientInfo->session_id)
		{
			int session_id = generateSessionId();
			clientInfo->session_id = session_id;
		}
		msg.session_id = clientInfo->session_id;
		sendSuccessResponse(clientInfo->socket, msg.seq, msg.session_id);
	}
	else
	{
		sendFailureResponse(clientInfo->socket, COULD_NOT_OPEN_ERROR_CODE, "The video requested could not be opened.", msg.seq);
	}
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
void sendFrameToClient(union sigval sv_data)
{
	RTSPClient *clientInfo = (RTSPClient*) sv_data.sival_ptr;

	CvCapture *video = clientInfo->video;

	char dollar_sign = DOLLAR_SIGN;
	char channel = 0;

	uint8_t rtp_version_byte = 2 << 6;
	uint8_t payload_type = JPEG_PAYLOAD_TYPE;

	uint32_t timestamp = 0;
	uint32_t ssrc = 0;
	printf("client rtp sequence number : %d", clientInfo->rtp_seq);

	IplImage* image = cvQueryFrame(video);
	if (!image) {
		pthread_mutex_lock(&clientInfo->clientLock);
		pausePlayback(clientInfo->playback_timer);
		pthread_mutex_unlock(&clientInfo->clientLock);
	    return;
	}
	else
	{
		CvMat* thumb = cvCreateMat(240, 320, CV_8UC3);
		cvResize(image, thumb, CV_INTER_AREA);
		const static int encodeParams[] = { CV_IMWRITE_JPEG_QUALITY, 30 };
		CvMat* encoded = cvEncodeImage(".jpeg", thumb, encodeParams);
		uint16_t payload_size = encoded->cols;
		uint16_t packet_size = 12 + payload_size;

		char payload_buffer[payload_size];
		memcpy(&payload_buffer, encoded->data.ptr, payload_size);
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
		memcpy(&packet_buffer[16], &payload_buffer, payload_size);

		int total = 0;
		int bytes_left = sizeof(packet_buffer);
		int n;
		while(total < sizeof(packet_buffer))
		{
			n = send(clientInfo->socket, packet_buffer + total, bytes_left, 0);
			if (n == -1) {break;}
			total += n;
			bytes_left -= n;
		}
	}
	pthread_mutex_lock(&clientInfo->clientLock);
	int scale = clientInfo->scale;
	int new_current_frame = clientInfo->current_frame_index + scale;
	if (new_current_frame >= 0)
	{
		clientInfo->current_frame_index = new_current_frame;
		cvSetCaptureProperty(video, CV_CAP_PROP_POS_FRAMES, clientInfo->current_frame_index);
		clientInfo->rtp_seq++;
	}
	else
	{
		clientInfo->current_frame_index = 0;
		cvSetCaptureProperty(video, CV_CAP_PROP_POS_FRAMES, clientInfo->current_frame_index);
		pausePlayback(clientInfo->playback_timer);
	}
	pthread_mutex_unlock(&clientInfo->clientLock);
}

void startPlayback(RTSPClient* clientInfo)
{
	PlaybackTimer* playbackTimer = clientInfo->playback_timer;
	if (!playbackTimer->play_interval.it_interval.tv_nsec)
	{
		memset(&playbackTimer->play_event, 0, sizeof(playbackTimer->play_event));
		playbackTimer->play_event.sigev_notify = SIGEV_THREAD;
		playbackTimer->play_event.sigev_value.sival_ptr = clientInfo;
		playbackTimer->play_event.sigev_notify_function = sendFrameToClient;
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
	printf("teardown2\n");
	if (clientInfo->video)
	{
		printf("teardown3\n");
		cvReleaseCapture(&clientInfo->video);
		printf("teardown4\n");
	}
	clientInfo->session_id = 0;
	printf("teardown5\n");
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
	cvReleaseCapture(&clientInfo->video);
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
    
