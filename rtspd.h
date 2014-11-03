typedef struct{
	//state;
	//hostName;
	const char* port;
	int sockfd;
} RTSPServer;

int initServer(RTSPServer *server);

int waitForConnections(RTSPServer *server);

