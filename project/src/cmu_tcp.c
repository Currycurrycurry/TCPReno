#include "cmu_tcp.h"

/*
 * Param: dst - The structure where socket information will be stored
 * Param: flag - A flag indicating the type of socket(Listener / Initiator)
 * Param: port - The port to either connect to, or bind to. (Based on flag)
 * Param: ServerIP - The server IP to connect to if the socket is an initiator.
 *
 * Purpose: To construct a socket that will be used in various connections.
 *  The initiator socket can be used to connect to a listener socket.
 *
 * Return: The newly created socket will be stored in the dst parameter,
 *  and the value returned will provide error information. 
 *
 */
int cmu_socket(cmu_socket_t * dst, int flag, int port, char * serverIP){
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0){
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  dst->their_port = port;
  dst->socket = sockfd;
  dst->received_buf = NULL;
  dst->received_len = 0;
  pthread_mutex_init(&(dst->recv_lock), NULL);
  dst->sending_buf = NULL;
  dst->sending_len = 0;
  pthread_mutex_init(&(dst->send_lock), NULL);
  dst->type = flag;
  dst->dying = FALSE;
  pthread_mutex_init(&(dst->death_lock), NULL);
  dst->window.last_ack_received = 0;
  dst->window.last_seq_received = 0;
  dst->window.send_wnd = create_pkt_window();
  dst->window.recv_wnd = create_pkt_window();
  pthread_mutex_init(&(dst->window.ack_lock), NULL);

  if(pthread_cond_init(&dst->wait_cond, NULL) != 0){
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }


  switch(flag){
    case(TCP_INITATOR):
      if(serverIP == NULL){
        perror("ERROR serverIP NULL");
        return EXIT_ERROR;
      }
      memset(&conn, 0, sizeof(conn));          
      conn.sin_family = AF_INET;          
      conn.sin_addr.s_addr = inet_addr(serverIP);  
      conn.sin_port = htons(port); 
      dst->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *) &my_addr,
        sizeof(my_addr)) < 0){
        perror("ERROR on binding");
        return EXIT_ERROR;
      }

      break;

    case(TCP_LISTENER):
      bzero((char *) &conn, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((unsigned short)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
           (const void *)&optval , sizeof(int));
      if (bind(sockfd, (struct sockaddr *) &conn,
        sizeof(conn)) < 0){
          perror("ERROR on binding");
          return EXIT_ERROR;
      }
      dst->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  getsockname(sockfd, (struct sockaddr *) &my_addr, &len);
  dst->my_port = ntohs(my_addr.sin_port);

  uint32_t seq, ack;
  char recv[DEFAULT_HEADER_LEN];
  socklen_t conn_len = sizeof(dst->conn);
  switch (flag){
      /*
       * client send the first and third packets
       * receive the second packet
      */
      case (TCP_INITATOR):
          seq = (unsigned int)(rand());
          char* first_packet_buf;
          first_packet_buf = create_packet_buf(dst->my_port, dst->their_port,seq,0,
                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK,32,0,NULL,NULL,0);

          sendto(sockfd, first_packet_buf, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(dst->conn), conn_len);
          free(first_packet_buf);

          recvfrom(dst->socket, recv, DEFAULT_HEADER_LEN, 0,(struct sockaddr *) &(dst->conn), &conn_len);
          if(!(get_flags(recv) & SYN_FLAG_MASK)||!(get_flags(recv) & ACK_FLAG_MASK)){
              //not a SYN_FLAG or ACK_FLAG
              return EXIT_ERROR;
          }
          while(pthread_mutex_lock(&(dst->window.ack_lock))!=0);
          dst->window.last_ack_received = get_ack(recv);
          dst->window.last_seq_received = get_seq(recv);
          pthread_mutex_unlock(&(dst->window.ack_lock));

          seq = get_ack(recv);
          ack = get_seq(recv)+1;
          char* third_packet_buf;
          third_packet_buf = create_packet_buf(dst->my_port, dst->their_port,seq,ack,
                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK,32,0,NULL,NULL,0);

          sendto(sockfd, third_packet_buf, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(dst->conn), conn_len);
          free(third_packet_buf);

          break;
      /*
       * server send the second packet
       * receive the first and third packets
       */
      case (TCP_LISTENER):
          recvfrom(dst->socket, recv, DEFAULT_HEADER_LEN, 0,(struct sockaddr *) &(dst->conn), &conn_len);
          if(!(get_flags(recv) & SYN_FLAG_MASK)){
              //not a SYN_FLAG
              return EXIT_ERROR;
          }
          while(pthread_mutex_lock(&(dst->window.ack_lock))!=0);
          dst->window.last_ack_received = get_ack(recv);
          dst->window.last_seq_received = get_seq(recv);
          pthread_mutex_unlock(&(dst->window.ack_lock));

          seq = (unsigned int)(rand());
          ack = get_seq(recv)+1;

          char* second_packet_buf;
          second_packet_buf = create_packet_buf(dst->my_port, dst->their_port,seq,ack,
                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK|ACK_FLAG_MASK,32,0,NULL,NULL,0);

          sendto(sockfd, second_packet_buf, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(dst->conn), conn_len);
          free(second_packet_buf);

          memset(&recv, 0, sizeof(recv));
          recvfrom(dst->socket, recv, DEFAULT_HEADER_LEN, 0,(struct sockaddr *) &(dst->conn), &conn_len);
          if(!(get_flags(recv) & ACK_FLAG_MASK)){
              //not a ACK_FLAG
              return EXIT_ERROR;
          }
          while(pthread_mutex_lock(&(dst->window.ack_lock))!=0);
          dst->window.last_ack_received = get_ack(recv);
          dst->window.last_seq_received = get_seq(recv);
          pthread_mutex_unlock(&(dst->window.ack_lock));

          break;
      default:
          perror("Unknown Flag");
          return EXIT_ERROR;
  }

  pthread_create(&(dst->thread_id), NULL, begin_backend, (void *)dst);  
  return EXIT_SUCCESS;
}

/**
 *  当没有数据需要发送时，并且重发已经完成时结束backend线程
 *
 */
void close_backend(cmu_socket_t * dst) {
  int buf_len;
  //unchecked_pkt_num;
  while(TRUE) {
    //while(pthread_mutex_lock(&(dst->send_window_lock)) != 0);
    //unchecked_pkt_num = dst->window.send_wnd->next - dst->window.send_wnd->front; //没有确认的数据包数量
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len; //没有发送的缓存的长度
    if(buf_len == 0){
      pthread_mutex_unlock(&(dst->send_lock));
      //pthread_mutex_unlock(&(dst->send_window_lock));
      break;
    }
    pthread_mutex_unlock(&(dst->send_lock));
    //pthread_mutex_unlock(&(dst->send_window_lock));
  }

  while(pthread_mutex_lock(&(dst->death_lock)) != 0);
  dst->dying = TRUE;
  pthread_mutex_unlock(&(dst->death_lock));
  //begin_backend(dst);
  pthread_exit(NULL);
#ifdef PKT_DEBUG
    fprintf(stdout,"After the initator send the last ack, he recv a packet which means the last ack is lost. He would send last ack again.\n");
#endif
  // terminator another thread
  pthread_join(dst->thread_id, NULL);

}


/*
 * Param: sock - The socket to close.
 *
 * Purpose: To remove any state tracking on the socket.
 *
 * Return: Returns error code information on the close operation.
 *
 */
int cmu_close(cmu_socket_t * sock){

  close_backend(sock);

  if(sock->type == TCP_INITATOR)
    fdu_initator_disconnect(sock);
  else
    fdu_listener_disconnect(sock);

  if(sock != NULL){
    if(sock->received_buf != NULL)
      free(sock->received_buf);
    if(sock->sending_buf != NULL)
      free(sock->sending_buf);
  }
  else{
    perror("ERORR Null scoket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

/*
 * Param: sock - The socket to read data from the received buffer.
 * Param: dst - The buffer to place read data into.
 * Param: length - The length of data the buffer is willing to accept.
 * Param: flags - Flags to signify if the read operation should wait for
 *  available data or not.
 *
 * Purpose: To retrive data from the socket buffer for the user application.
 *
 * Return: If there is data available in the socket buffer, it is placed
 *  in the dst buffer, and error information is returned. 
 *
 */
int cmu_read(cmu_socket_t * sock, char* dst, int length, int flags){
  char* new_buf;
  int read_len = 0;

  if(length < 0){
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while(pthread_mutex_lock(&(sock->recv_lock)) != 0);

  switch(flags){
    case NO_FLAG:
      while(sock->received_len == 0){
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock)); 
      }
    case NO_WAIT:
      if(sock->received_len > 0){
        if(sock->received_len > length)
          read_len = length;
        else
          read_len = sock->received_len;

        memcpy(dst, sock->received_buf, read_len);
        if(read_len < sock->received_len){
           new_buf = malloc(sock->received_len - read_len);
           memcpy(new_buf, sock->received_buf + read_len, 
            sock->received_len - read_len);
           free(sock->received_buf);
           sock->received_len -= read_len;
           sock->received_buf = new_buf;
        }
        else{
          free(sock->received_buf);
          sock->received_buf = NULL;
          sock->received_len = 0;
        }
      }
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

/*
 * Param: sock - The socket which will facilitate data transfer.
 * Param: src - The data source where data will be taken from for sending.
 * Param: length - The length of the data to be sent.
 *
 * Purpose: To send data to the other side of the connection.
 *
 * Return: Writes the data from src into the sockets buffer and
 *  error information is returned. 
 *
 */
int cmu_write(cmu_socket_t * sock, char* src, int length){
  while(pthread_mutex_lock(&(sock->send_lock)) != 0);
  if(sock->sending_buf == NULL)
    sock->sending_buf = malloc(length);
  else
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  memcpy(sock->sending_buf + sock->sending_len, src, length);
  sock->sending_len += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}

/*
 * wait for ACK for a time_out and check it
 */
int wait_ACK_time_out(cmu_socket_t * sock, uint32_t expect_ack, uint32_t expect_seq){
  fd_set fdu_ack;
  ssize_t lenght = 0;
  struct timeval time_out;
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  uint32_t pktlen = 0;
  uint32_t buf_size = 0;
  uint32_t n = 0;
  socklen_t conn_len = sizeof(sock->conn);
  time_out.tv_sec = CONNECT_TIME_OUT / 1000;
  time_out.tv_usec = (CONNECT_TIME_OUT % 1000) * 1000;

  FD_ZERO(&fdu_ack);
  FD_SET(sock->socket, &fdu_ack);

  //loss the data or error
  if(select(sock->socket+1, &fdu_ack, NULL, NULL, &time_out) <= 0){
    return -1;
  }
  lenght = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *) &(sock->conn), &conn_len);

  if(lenght >= DEFAULT_HEADER_LEN){
    //the length of pkt, contains the header
    pktlen = get_plen(hdr);
    pkt = malloc(pktlen);
    //read the whole packet
    while(buf_size < pktlen){
      n = recvfrom(sock->socket, pkt + buf_size, pktlen - buf_size,
                   NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      //read the ip and port of the other
      buf_size = buf_size + n;
    }
    //read and remove it to make sure no dumplication in the pipe
    free(pkt);
    if(get_flags(hdr) == ACK_FLAG_MASK && (expect_ack == 0 || get_ack(hdr) == expect_ack) && (expect_seq == 0 || get_seq(hdr) == expect_seq) ){
#ifdef ACK_DEBUG
      fprintf(stdout,"recv ACK packet with ack %d and seq %d.\n", get_ack(hdr), get_seq(hdr));
#endif
      return 1;
    }
    // recieve the FIN pkt
    if(get_flags(hdr) == FIN_FLAG_MASK){
#ifdef PKT_DEBUG
      fprintf(stdout,"recv FIN packet with ack %d and seq there===========%d.\n", get_ack(hdr), get_seq(hdr));
#endif
      // response with ack right now
      send_ACK(sock, sock->window.send_wnd->next, get_seq(hdr) + 1);
    }
  }
  return -1;
}

/*
 * wait for the FIN pkt from the server without block
 */
int wait_FIN_no_wait(cmu_socket_t * sock){
  ssize_t lenght = 0;
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  uint32_t plen = 0;
  uint32_t buf_size = 0;
  uint32_t n = 0;
  socklen_t conn_len = sizeof(sock->conn);

  lenght = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *) &(sock->conn), &conn_len);

  if(lenght >= DEFAULT_HEADER_LEN){
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while(buf_size < plen){
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size,
                   NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    free(pkt);
    if(get_flags(hdr) == FIN_FLAG_MASK){
#ifdef PKT_DEBUG
      fprintf(stdout,"recv FIN packet with ack %d and seq %d.\n", get_ack(hdr), get_seq(hdr));
#endif
      sock->window.recv_wnd->next = get_seq(hdr) + 1;
      return 1;
    }
  }
  return -1;
}
/*
 * wait for any pkt from the server without block
 */
int initator_wait_any_packet_no_wait(cmu_socket_t * sock){
  ssize_t len = 0;
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  uint32_t plen = 0;
  uint32_t buf_size = 0;
  uint32_t n = 0;
  socklen_t conn_len = sizeof(sock->conn);

  len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *) &(sock->conn), &conn_len);

  if(len >= DEFAULT_HEADER_LEN){
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while(buf_size < plen){
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size,
                   NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    free(pkt);
#ifdef PKT_DEBUG
    fprintf(stdout,"After the initator send the last ack, he recv a packet which means the last ack is lost. He would send last ack again.\n");
#endif
    sock->window.recv_wnd->next = get_seq(hdr) + 1;
    return 1;
  }
  return -1;
}

/*
 * disconnect from the initator like client
 */
void fdu_initator_disconnect(cmu_socket_t * dst){
  size_t conn_len = sizeof(dst->conn);
  char *rsp;

#ifdef PROCESS_DEBUG
  fprintf(stdout,"The child thread of the client is over.\n");
#endif

  //cyclely send a FIN pkt to server for a disconnection, and wait for an ACK, if recieved then jump out
  while(TRUE){
    rsp = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port), dst->window.send_wnd->next, dst->window.recv_wnd->next,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);
#ifdef PKT_DEBUG
    fprintf(stdout,"send FIN packet with ack %d and seq %d.\n", dst->window.recv_wnd->next, dst->window.send_wnd->next);
#endif
    sendto(dst->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(dst->conn), conn_len);

    if(wait_ACK_time_out(dst,dst->window.send_wnd->next + 1,0) > 0) {
      //dst->connection.disconnect = FIN_WAIT_2;
      break;
    }
  }
  free(rsp);
  while(TRUE){
    //wait for FIN pkt without wait , if recieve then jump out
    if(wait_FIN_no_wait(dst) > 0) {
      send_ACK(dst, dst->window.send_wnd->next, dst->window.recv_wnd->next);
      //dst->connection.disconnect == TIME_WAIT;
      break;
    }
  }

#ifdef PROCESS_DEBUG
  fprintf(stdout,"Now the initator has sent the last ack and wait %d ms to disconnect.\n",3000);
#endif

  struct timeval current;
  struct timeval timer;
  gettimeofday(&timer, NULL);
  // at the moment it is TIME_WAIT ,cyclely check whether time_out and check whether recieve pkt, if recieve the answer ACK and restart the timer
  while(TRUE) {
    gettimeofday(&current, NULL);
    //whether time out
    if(current.tv_sec - timer.tv_sec > 3000 / 1000) {
      break;
    }
    //if recieve pkt , then it means last ack loss
    if(initator_wait_any_packet_no_wait(dst) > 0){
      // answer ack if recieve anything
      send_ACK(dst, dst->window.send_wnd->next, dst->window.recv_wnd->next);
#ifdef PROCESS_DEBUG
      fprintf(stdout,"Now the initator has sent the last ack and wait %d ms to disconnect.\n",3000);
#endif
      //restart the timer
      gettimeofday(&timer, NULL);
    }
  }
#ifdef PROCESS_DEBUG
  fprintf(stdout,"Now the initator begins to disconnect.\n",3000);
#endif
}

void fdu_listener_disconnect(cmu_socket_t * sock){
  size_t conn_len = sizeof(sock->conn);
#ifdef PROCESS_DEBUG
  fprintf(stdout,"The child thread of the server is over.\n");
#endif
  char* rsp;

    while(TRUE) {
      if(wait_FIN_no_wait(sock) > 0){
        //sock->connection.disconnect == CLOSE_WAIT;
        send_ACK(sock,(sock->window).send_wnd->next, (sock->window).recv_wnd->next);
        break;
      }
    }

  rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), sock->window.send_wnd->next, sock->window.recv_wnd->next,
                          DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);

  //sock->connection.disconnect = LAST_ACK;

  while(TRUE){
#ifdef PKT_DEBUG
    fprintf(stdout,"send FIN packet with ack %d and seq %d.\n", sock->window.recv_wnd->next, sock->window.send_wnd->next);
#endif
    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len);
    if(wait_ACK_time_out(sock,sock->window.send_wnd->next + 1,0) > 0) {
      //sock->connection.disconnect == CLOSED;
      break;
    }
  }
  free(rsp);
}

