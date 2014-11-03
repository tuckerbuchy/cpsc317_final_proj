typedef struct server_ {
	//state;
	//hostName;
	const char* port;
	int sockfd;
} server_;

int initServer(server_ *server);

