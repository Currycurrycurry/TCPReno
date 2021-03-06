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
  char buf[RCVBUFFER];
  int read, n;
  FILE *fp;

  cmu_write(sock, "hi there", 9);
  sleep(3);
  n = cmu_read(sock, buf, 200, NO_FLAG);
  printf("R: %s\n", buf);
  printf("N: %d\n", n);

  // fp = fopen("./test/testfile_19M.pdf", "rb");
  fp = fopen("./src/cmu_tcp.c", "rb");
  // fp = fopen("./test/random.input", "rb");
  // printf("*** finish fp open ***");
  n = 0;
  read = 1;
  while (read > 0) {
    read = fread(buf, 1, RCVBUFFER, fp);
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

  // struct timeval start_time;
  // struct timeval end_time;
  // gettimeofday(&start_time,NULL);
  functionality(&socket);
  // gettimeofday(&end_time,NULL);
  LOG_DEBUG("client finished");
  // long int time = end_time.tv_sec-start_time.tv_sec;
  // LOG_DEBUG("***The total client send time is [%ld] s***",time);

  if (cmu_close(&socket) < 0) exit(EXIT_FAILURE);
  return EXIT_SUCCESS;
}
