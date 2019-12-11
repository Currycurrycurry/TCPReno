#include <stdlib.h>
#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t *sock) {
  char buf[9898];
  int read, n;
  FILE *fp;

  cmu_write(sock, "hi there", 9);
  sleep(3);
  n = cmu_read(sock, buf, 200, NO_FLAG);
  printf("R: %s\n", buf);
  printf("N: %d\n", n);

  fp = fopen("./src/cmu_tcp.c", "rb");
  n = 0;
  read = 1;
  while (read > 0) {
    read = fread(buf, 1, 9898, fp);
    if (read > 0) cmu_write(sock, buf, read);
    n += read;
  }
  LOG_DEBUG("client send %d bytes", n);
}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample initiator for the TCP connection to a
 *  listener.
 *
 */
int main(int argc, char **argv) {
  srand((unsigned)time(0) + 2333);
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (serverip)
    ;
  else {
    // serverip = "0.0.0.0";
    serverip = "10.0.0.1";
  }

  serverport = getenv("serverport15441");
  if (serverport)
    ;
  else {
    serverport = "15441";
  }
  portno = (unsigned short)atoi(serverport);

  if (cmu_socket(&socket, TCP_INITATOR, portno, serverip) < 0) {
    printf("socket initialize error, bad return code\n");
    exit(EXIT_FAILURE);
  }

  functionality(&socket);
  while(1);

  if (cmu_close(&socket) < 0) exit(EXIT_FAILURE);
  return EXIT_SUCCESS;
}
