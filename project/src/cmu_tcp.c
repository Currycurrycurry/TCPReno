#include "cmu_tcp.h"

#define MAX_RETRY 5

/**
 * @brief fdu_initiator_connect connects the socket as an initiator.
 *
 * It works in the following steps:
 * 1. Create the SYN packet and use a maximum retry of 5, and a timeout of 3
 * seconds for each trial to send the packet and wait for the SYNACK response.
 * The status transition is from CLOSED to ESTABLISHED.
 * 2. Once the SYNACK response is received, the connection is actually
 * established, but we still want to send a pure ACK packet for respect, so we
 * create another response. Note that the response is not guaranteed to be
 * received, and if it is lost, the listener will still be in STATUS_LISTEN,
 * which can be troublesome, the solution is to carry an ACK number for
 * subsequent SYN packet
 * 3. Finally, we are now able to send and receive data from the other side, so
 * we initialize the window.sender and window.receiver, so that we are ready to
 *    send and receive.
 *
 * @param dst the socket that wants to connect.
 */
int fdu_initiator_connect(cmu_socket_t *dst) {
  LOG_DEBUG("entering initiator connect");
  dst->syn_seq = (unsigned int)(rand());
  dst->status = STATUS_CLOSED;

  socklen_t conn_len = sizeof(dst->conn);
  char *syn_packet_buf, *ack_packet_buf;

  // TODO(Zhifeng): double-check the adv_window = 32
  syn_packet_buf = create_packet_buf(
      dst->my_port, dst->their_port, dst->syn_seq, 0, DEFAULT_HEADER_LEN,
      DEFAULT_HEADER_LEN, SYN_FLAG_MASK, 32, 0, NULL, NULL, 0);

  int retry = 0;
  do {
    
    sendto(dst->socket, syn_packet_buf, DEFAULT_HEADER_LEN, 0,
           (struct sockaddr *)&(dst->conn), conn_len);
    dst->status = STATUS_SYN_SENT;
    check_for_data(dst, TIMEOUT);
    ++retry;
    LOG_INFO("%d th SYN packet sent", retry);
  } while (dst->status != STATUS_ESTABLISHED && retry < MAX_RETRY);
  free(syn_packet_buf);
  syn_packet_buf = NULL;

  if (retry == MAX_RETRY) {
    return EXIT_ERROR;
  }

  // for ACK packet, seq does not matter, so we set it to be 0, see
  // https://networkengineering.stackexchange.com/questions/48775/why-does-an-pure-ack-increment-the-sequence-number
  ack_packet_buf = create_packet_buf(dst->my_port, dst->their_port, 0,
                                     dst->window.last_seq_received + 1,
                                     DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                     ACK_FLAG_MASK, 32, 0, NULL, NULL, 0);
  sendto(dst->socket, ack_packet_buf, DEFAULT_HEADER_LEN, 0,
         (struct sockaddr *)&(dst->conn), conn_len);
  free(syn_packet_buf);

  // initialize sender
  dst->window.sender = (sender_window_t *)malloc(sizeof(sender_window_t));
  dst->window.sender->base =
      dst->syn_seq + 1;  // we'll start to send the first packet from here.
  dst->window.sender->nextseq = dst->window.sender->base;
  dst->window.sender->timeout.tv_sec = DEFAULT_TIMEOUT_SEC;
  dst->window.sender->timeout.tv_usec = DEFAULT_TIMEOUT_USEC;
  dst->window.sender->rwnd = RCVBUFFER - dst->received_len; // add for flow control

  dst->window.sender->cwnd = MSS;
  dst->window.sender->ssthresh = RCVBUFFER;
  dst->window.sender->congestion_status = SLOW_START;
  LOG_DEBUG("Set cwnd=MSS[%d],status=SLOW_START[%d],ssthresh=[%d]",dst->window.sender->cwnd,dst->window.sender->congestion_status,dst->window.sender->ssthresh);



  // initialize receiver
  // dst->window.receiver = create_pkt_window();
  dst->window.receiver = (receiver_window_t *)malloc(sizeof(receiver_window_t));
  dst->window.receiver->expect_seq = dst->window.last_seq_received + 1;
  memset(dst->window.receiver->marked, 0, sizeof(dst->window.receiver->marked));

  LOG_INFO("established: sender->base(%d) expect_seq(%d)",
           dst->window.sender->base, dst->window.receiver->expect_seq);
  return 0;
}

int fdu_listener_connect(cmu_socket_t *dst) {
  LOG_DEBUG("entering listener connect");
  dst->syn_seq = (unsigned int)(rand());
  dst->status = STATUS_LISTEN;

  // check for the first SYN handshake packet, it blocks. Upon receive, the
  // status turns into SYN_RCVD and an SYNACK response will be made.
  check_for_data(dst, NO_FLAG);


  LOG_DEBUG("seq exchanged, waiting for ack");

  // check for the ACK packet for establish the connection, it also blocks. If
  // the ACK packet misses, the first data SYN packet will also be valid to
  // unblock.
  do {
    check_for_data(dst, NO_FLAG);
  } while (dst->status != STATUS_ESTABLISHED);

  // initialize sender
  dst->window.sender = (sender_window_t *)malloc(sizeof(sender_window_t));
  dst->window.sender->base =
      dst->syn_seq + 1;  // we'll start to send the first packet from here.
  dst->window.sender->nextseq = dst->window.sender->base;
  dst->window.sender->timeout.tv_sec = DEFAULT_TIMEOUT_SEC;
  dst->window.sender->timeout.tv_usec = DEFAULT_TIMEOUT_USEC;
  dst->window.sender->rwnd = RCVBUFFER - dst->received_len; // add for flow control

  dst->window.sender->cwnd = MSS;
  dst->window.sender->ssthresh = RCVBUFFER;
  dst->window.sender->congestion_status = SLOW_START;
  LOG_DEBUG("Set cwnd=MSS[%d],status=SLOW_START[%d],ssthresh=[%d]",dst->window.sender->cwnd,dst->window.sender->congestion_status,dst->window.sender->ssthresh);

  // initialize receiver
  // dst->window.receiver = create_pkt_window();
  dst->window.receiver = (receiver_window_t *)malloc(sizeof(receiver_window_t));
  dst->window.receiver->expect_seq = dst->window.last_seq_received + 1;
  memset(dst->window.receiver->marked, 0, sizeof(dst->window.receiver->marked));

  LOG_INFO("established: sender->base(%d) expect_seq(%d)",
           dst->window.sender->base, dst->window.receiver->expect_seq);
  return 0;
}

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

int cmu_socket(cmu_socket_t *dst, int flag, int port, char *serverIP) {
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  int error;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
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
  pthread_mutex_init(&(dst->window.ack_lock), NULL);

  if (pthread_cond_init(&dst->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }

  // uint32_t seq, ack;
  // char recv[DEFAULT_HEADER_LEN];
  // socklen_t conn_len = sizeof(dst->conn);

  switch (flag) {
    case (TCP_INITATOR):
      if (serverIP == NULL) {
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
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
      LOG_INFO("bind local socket to port %d", ntohs(my_addr.sin_port));
      if ((error = fdu_initiator_connect(dst)) < 0) {
        return error;
      }

      break;

    case (TCP_LISTENER):
      bzero((char *)&conn, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((unsigned short)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      dst->conn = conn;

      if ((error = fdu_listener_connect(dst)) < 0) {
        return error;
      }
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }

  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  dst->my_port = ntohs(my_addr.sin_port);
  pthread_create(&(dst->thread_id), NULL, begin_backend, (void *)dst);
  return EXIT_SUCCESS;
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
int cmu_read(cmu_socket_t *sock, char *dst, int length, int flags) {
  char *new_buf;
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
    ;

  switch (flags) {
    case NO_FLAG:
      while (sock->received_len == 0) {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
      }
    case NO_WAIT:
      if (sock->received_len > 0) {
        if (sock->received_len > length){
          read_len = length;
        } 
        else{
          read_len = sock->received_len;
        }
        memcpy(dst, sock->received_buf, read_len);
        if (read_len < sock->received_len) {
          new_buf = malloc(sock->received_len - read_len);
          memcpy(new_buf, sock->received_buf + read_len,
                 sock->received_len - read_len);
          free(sock->received_buf);
          sock->received_len -= read_len;
          sock->received_buf = new_buf;
        
        } else {
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
int cmu_write(cmu_socket_t *sock, char *src, int length) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0)
    ;
  if (sock->sending_buf == NULL)
    sock->sending_buf = malloc(length);
  else
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  memcpy(sock->sending_buf + sock->sending_len, src, length);
  sock->sending_len += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}

//close函数由client或者server单独调用，被调用一方就是initiator disconnect，另一方自动为listener，根据sock的connection取到自己的sock套接字
void fdu_initator_disconnect(cmu_socket_t *dst) {
  LOG_DEBUG("entering disconnect at initiator:");
  size_t conn_len = sizeof(dst->conn);
  char *rsp;
  dst->status = STATUS_FIN_WAIT_1;
  LOG_DEBUG("initiator status : STATUS_FIN_WAIT_1");
  //阶段一：循环发送FIN pkt，将状态由established 设置为STATUS_FIN_WAIT_1
  while (TRUE) {
    rsp = create_packet_buf(dst->my_port, dst->conn.sin_port, dst->window.sender->nextseq,
                            dst->window.receiver->expect_seq,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(dst->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr *) &(dst->conn), conn_len);
    LOG_DEBUG("client_port:[%d] server_port:[%d]", dst->my_port, dst->their_port);

    //阶段二：接收到 ACK pkt，将状态由STATUS_FIN_WAIT_1设置为STATUS_FIN_WAIT_2
    if (wait_ACK_time_out(dst) > 0) {
      dst->status = STATUS_FIN_WAIT_2;
      LOG_DEBUG("initiator status : STATUS_FIN_WAIT_2");
      break;
    }
  }
  free(rsp);

  //阶段三：仍可接收普通数据包，循环同时注意接收FIN pkt，一旦收到，回复ACK同时，将状态由STATUS_FIN_WAIT_2 设置为TIME_WAIT
  while (TRUE) {
    if (wait_FIN_no_wait(dst) > 0) {  // 这里不等待尝试接受FIN包，接收到了退出循环
      send_ACK(dst, dst->window.sender->nextseq, dst->window.receiver->expect_seq);
      //dst->window.last_ack_received
      dst->status = STATUS_TIME_WAIT;
      LOG_DEBUG("initiator status : STATUS_TIME_WAIT");
      break;
    }
  }

  //阶段四：等待超时2ML
  struct timeval current;
  gettimeofday((struct timeval *)&(dst->window.sender->send_time), NULL);
  while (TRUE) {
    gettimeofday(&current, NULL);
    if (current.tv_sec - dst->window.sender->send_time.tv_sec > DEFAULT_TIMEOUT_SEC * 1000 / 1000) {
      dst->status =  STATUS_CLOSED;
      LOG_DEBUG("initiator status : STATUS_CLOSED");
      break;
    }
    // 当前状态是TIME_WAIT, 不断检查是否超时同时不断检查是否可以收到包，如果可以收到包，就回复ACK，重启计时器
    if (initator_wait_any_packet_no_wait(dst) > 0) {
      send_ACK(dst, dst->window.sender->nextseq,
               dst->window.receiver->expect_seq);                                           ///////////////////////////////
      gettimeofday((struct timeval *)&(dst->window.sender->send_time), NULL);
    }
  }
}

void fdu_listener_disconnect(cmu_socket_t *sock){
  LOG_DEBUG("entering disconnect at listener:");
  size_t conn_len = sizeof(sock->conn);
  //cmu_socket_t *sock = dst->
  char *rsp;
  //阶段一：循环接收FIN pkt，一旦接收到状态由established 转换为CLOSE_WAIT,并发送ACK
  if(sock->status != STATUS_CLOSE_WAIT){

    LOG_DEBUG("server_port:[%d] client_port:[%d]",sock->my_port, ntohs(sock->conn.sin_port));
    rsp = create_packet_buf(sock->my_port, sock->conn.sin_port, sock->window.sender->nextseq, sock->window.receiver->expect_seq,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    while(TRUE) {

      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len);
      if(wait_ACK_time_out(sock) > 0) {
        LOG_DEBUG("listener status : STATUS_FIN_WAIT_2");
        break;
      }
    }
    sock->window.sender->nextseq++;
    free(rsp);

    //阶段二：确认没有数据需要发送后，循环发送FIN pkt，并将状态改为LAST_ACK
    while(TRUE){

      if(wait_FIN_no_wait(sock) > 0){
        sock->status = STATUS_CLOSE_WAIT;
        LOG_DEBUG("listener status : CLOSE_WAIT");
        send_ACK(sock,sock->window.sender->nextseq,sock->window.receiver->expect_seq);
        break;
      }
    }
  }

  rsp = create_packet_buf(sock->my_port, sock->conn.sin_port, sock->window.sender->nextseq, sock->window.receiver->expect_seq,
                          DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);

  sock->status = STATUS_LAST_ACK;
  LOG_DEBUG("listener status : STATUS_LAST_ACK");

  while(TRUE){

    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) &(sock->conn), conn_len);
    if(wait_ACK_time_out(sock) > 0) {
      sock->status = STATUS_CLOSED;
      LOG_DEBUG("listener status : STATUS_CLOSED");
      break;
    }
  }

  free(rsp);

}

// 释放socK的内存的同时关闭监听描述符
int free_cmu_socket(cmu_socket_t * sock) {
  if(sock != NULL){
    if(sock->received_buf != NULL)
      free(sock->received_buf);
    if(sock->sending_buf != NULL)
      free(sock->sending_buf);
    LOG_DEBUG("freed received_buf and sending_buf now");
//    if(sock->timer != NULL) {
//      free(sock->timer);
//    }
    if(sock->window.receiver != NULL) {
      free(sock->window.receiver);
      LOG_DEBUG("freed receiver now");
    }
    if(sock->window.sender != NULL) {
//      for(int i = 0; i < sock->window.sender->window_size; i++) {
//          LOG_DEBUG("=====[%d]",i);
//        if(sock->window.sender->win_packet_buffer[i] != NULL) {
//          free(sock->window.sender->win_packet_buffer[i]);
//        }
//      }
      free(sock->window.sender);
      LOG_DEBUG("freed sender now");
    }
    LOG_DEBUG("freed sock now");
  }
  else{
    perror("ERORR Null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

/**
 *  当没有数据需要发送时，并且重发已经完成时结束backend线程
 *
 */
void close_backend(cmu_socket_t * dst) {
  int unchecked_pkt_num,buf_len;
  while(TRUE) {
    //while(pthread_mutex_lock(&(dst->send_window_lock)) != 0);
    unchecked_pkt_num = dst->window.sender->nextseq - dst->window.sender->base; //没有确认的数据包数量
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len; //没有发送的缓存的长度
    if(buf_len == 0 && unchecked_pkt_num==0){
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

  pthread_join(dst->thread_id, NULL); // 结束另外一个线程
}


int cmu_close(cmu_socket_t * sock) {

/*
 * Param: sock - The socket to close.
 *
 * Purpose: To remove any state tracking on the socket.
 *
 * Return: Returns error code information on the close operation.
 *
 */

  close_backend(sock);
  LOG_DEBUG("sock close backend");
  if(sock->type == TCP_INITATOR)
    fdu_initator_disconnect(sock);
  else
    fdu_listener_disconnect(sock);

  return free_cmu_socket(sock);

}

int wait_ACK_time_out(cmu_socket_t * sock){
  // 在一定的时间内等待ACK，并做相关验证
  // case WAIT_ACK_FIN_TIMEOUT:
  fd_set ackFD;
  ssize_t len = 0;
  struct timeval time_out;
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  uint32_t expect_ack = sock->window.sender->nextseq + 1;
  uint32_t expect_seq = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  socklen_t conn_len = sizeof(sock->conn);
  time_out.tv_sec = CONNECT_TIME_OUT / 1000;
  time_out.tv_usec = (CONNECT_TIME_OUT % 1000) * 1000;
  FD_ZERO(&ackFD);
  FD_SET(sock->socket, &ackFD);
  if(select(sock->socket+1, &ackFD, NULL, NULL, &time_out) <= 0){ // 没有等到数据或者出错
    return -1;
  }
  len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *) &(sock->conn), &conn_len);
  if(len >= DEFAULT_HEADER_LEN){
    plen = get_plen(hdr); // 包长度，含头部
    pkt = malloc(plen);
    while(buf_size < plen){ // 读出整个包，网络是个流管道，不读取的话下一次会读到，影响通信
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size,
                   NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      // 从udp中获取对方的ip和端口，存在sock->conn
      // 读取数据并移除
      buf_size = buf_size + n;
    }
    free(pkt);
    if(get_flags(hdr) == ACK_FLAG_MASK && (expect_ack == 0 || get_ack(hdr) == expect_ack) && (expect_seq == 0 || get_seq(hdr) == expect_seq) ){
      return 1;
    }
    if(get_flags(hdr) == FIN_FLAG_MASK){
      send_ACK(sock, sock->window.sender->nextseq, get_seq(hdr) + 1);
    }
  }
  return -1;
}

int wait_FIN_no_wait(cmu_socket_t * sock){
  // case WAIT_FIN_TIMEOUT:
  ssize_t len = 0;
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  uint32_t plen = 0, buf_size = 0, n = 0;
  socklen_t conn_len = sizeof(sock->conn);

  len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *) &(sock->conn), &conn_len);

  if(len >= DEFAULT_HEADER_LEN){
    plen = get_plen(hdr); // 包长度，含头部
    pkt = malloc(plen);
    while(buf_size < plen){ // 读出整个包，网络是个流管道，不读取的话下一次会读到，影响通信
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size,
                   NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      // 从udp中获取对方的ip和端口，存在sock->conn
      // 读取数据并移除
      buf_size = buf_size + n;
    }
    free(pkt);
    if(get_flags(hdr) == FIN_FLAG_MASK){
      sock->window.receiver->expect_seq = get_seq(hdr) + 1; 
      return 1;
    }else{
      uint32_t ack = get_seq(hdr) + get_plen(hdr) - DEFAULT_HEADER_LEN;
      send_ACK(sock, sock->window.sender->nextseq,ack );
      LOG_DEBUG("!!!STILL DATA PACKET TO RECEIVE!!!");
      // sock->window.receiver->expect_seq += get_plen(hdr) - DEFAULT_HEADER_LEN;
    }
  }
  return -1;
}

int initator_wait_any_packet_no_wait(cmu_socket_t * sock) {
  //case WAIT_ANY_PKT:
  ssize_t len = 0;
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  uint32_t plen = 0;
  uint32_t buf_size = 0;
  uint32_t n = 0;
  socklen_t conn_len = sizeof(sock->conn);

  len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *) &(sock->conn), &conn_len);

  if (len >= DEFAULT_HEADER_LEN) {
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size,
                   NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    free(pkt);

    sock->window.receiver->expect_seq = get_seq(hdr) + 1;
    return 1;
  }
  return -1;
}
