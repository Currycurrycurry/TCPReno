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
  char buf[23333];
  FILE *fp;
  int n, read;

  n = cmu_read(sock, buf, 200, NO_FLAG);
  printf("R: %s\n", buf);
  printf("N: %d\n", n);
  cmu_write(sock, "hi there", 9);
  sleep(10);

  n = 0;
  while (n < 15706) {
    read = cmu_read(sock, buf + n, 23333, NO_FLAG);
    n += read;
  }
  printf("N: %d\n", n);
  fp = fopen("./test/file.c", "w+");
  fwrite(buf, 1, n, fp);
}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample listener for the TCP connection.
 *
 */
int main(int argc, char **argv) {
  srand((unsigned)time(0) + 233);
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (serverip)
    ;
  else {
    // use 0.0.0.0 to test on localhost
    serverip = "0.0.0.0";
    // serverip = "10.0.0.1";
  }

  serverport = getenv("serverport15441");
  if (serverport)
    ;
  else {
    serverport = "15441";
  }
  portno = (unsigned short)atoi(serverport);

  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    LOG_ERROR("socket initialize error, bad return code");
    exit(EXIT_FAILURE);
  }

  functionality(&socket);
  LOG_DEBUG("server finished");
  while(1);

  if (cmu_close(&socket) < 0) exit(EXIT_FAILURE);
  return EXIT_SUCCESS;
}
