#include <stdio.h>
#include <stdlib.h>
#include "rtspd.h"

int main(int argc,  const char* argv[]){
	RTSPServer server;
	// /server = (RTSPServer *) malloc(sizeof (RTSPServer));

  if (argc < 2) {
    fprintf(stderr, "error: port not informed. Usage:\n\t%s PORT\n", argv[0]);
    return 1;
  }

  server.port = argv[1];
  initServer(&server);
  waitForConnections(&server);
  return 0;
}
