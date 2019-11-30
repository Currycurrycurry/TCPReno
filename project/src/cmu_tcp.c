#include "cmu_tcp.h"

int fdu_initiator_connect(cmu_socket_t *dst)
{
  char recv[DEFAULT_HEADER_LEN];
  uint32_t seq = (unsigned int)(rand()), ack;
  socklen_t conn_len = sizeof(dst->conn);
  char *first_packet_buf;

  first_packet_buf = create_packet_buf(dst->my_port, dst->their_port, seq, 0,
                                       DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK, 32, 0, NULL, NULL, 0);

  sendto(dst->socket, first_packet_buf, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), conn_len);
  free(first_packet_buf);

  recvfrom(dst->socket, recv, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), &conn_len);//block 

  if (!(get_flags(recv) & SYN_FLAG_MASK) || !(get_flags(recv) & ACK_FLAG_MASK))
  {
    //not a SYN_FLAG or ACK_FLAG
    return EXIT_ERROR;
  }
  while (pthread_mutex_lock(&(dst->window.ack_lock)) != 0)
    ;
  dst->window.last_ack_received = get_ack(recv);
  dst->window.last_seq_received = get_seq(recv);
  pthread_mutex_unlock(&(dst->window.ack_lock));

  seq = get_ack(recv);
  ack = get_seq(recv) + 1;
  char *third_packet_buf;
  third_packet_buf = create_packet_buf(dst->my_port, dst->their_port, seq, ack,
                                       DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 32, 0, NULL, NULL, 0);

  sendto(dst->socket, third_packet_buf, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), conn_len);
  free(third_packet_buf);
  return 0;
}

int fdu_listener_connect(cmu_socket_t *dst)
{
  char recv[DEFAULT_HEADER_LEN];
  socklen_t conn_len = sizeof(dst->conn);
  recvfrom(dst->socket, recv, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), &conn_len);
  if (!(get_flags(recv) & SYN_FLAG_MASK))
  {
    //not a SYN_FLAG
    return EXIT_ERROR;
  }
  while (pthread_mutex_lock(&(dst->window.ack_lock)) != 0)
    ;
  dst->window.last_ack_received = get_ack(recv);
  dst->window.last_seq_received = get_seq(recv);
  pthread_mutex_unlock(&(dst->window.ack_lock));

  uint32_t seq = (unsigned int)(rand());
  uint32_t ack = get_seq(recv) + 1;

  char *second_packet_buf;
  second_packet_buf = create_packet_buf(dst->my_port, dst->their_port, seq, ack,
                                        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK | ACK_FLAG_MASK, 32, 0, NULL, NULL, 0);

  sendto(dst->socket, second_packet_buf, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), conn_len);
  free(second_packet_buf);

  memset(&recv, 0, sizeof(recv));
  recvfrom(dst->socket, recv, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), &conn_len);
  if (!(get_flags(recv) & ACK_FLAG_MASK))
  {
    //not a ACK_FLAG
    return EXIT_ERROR;
  }
  while (pthread_mutex_lock(&(dst->window.ack_lock)) != 0)
    ;
  dst->window.last_ack_received = get_ack(recv);
  dst->window.last_seq_received = get_seq(recv);
  pthread_mutex_unlock(&(dst->window.ack_lock));

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
int cmu_socket(cmu_socket_t *dst, int flag, int port, char *serverIP)
{
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0)
  {
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
  // dst->window.send_wnd = create_pkt_window();
  dst->window.receiver = create_pkt_window();
  pthread_mutex_init(&(dst->window.ack_lock), NULL);

  if (pthread_cond_init(&dst->wait_cond, NULL) != 0)
  {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }


  // uint32_t seq, ack;
  // char recv[DEFAULT_HEADER_LEN];
  // socklen_t conn_len = sizeof(dst->conn);

  switch (flag)
  {
  case (TCP_initiator):
    if (serverIP == NULL)
    {
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
    if (bind(sockfd, (struct sockaddr *)&my_addr,
             sizeof(my_addr)) < 0)
    {
      perror("ERROR on binding");
      return EXIT_ERROR;
    }
    fdu_initiator_connect(dst);

    break;

  case (TCP_LISTENER):
    bzero((char *)&conn, sizeof(conn));
    conn.sin_family = AF_INET;
    conn.sin_addr.s_addr = htonl(INADDR_ANY);
    conn.sin_port = htons((unsigned short)port);

    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval, sizeof(int));
    if (bind(sockfd, (struct sockaddr *)&conn,
             sizeof(conn)) < 0)
    {
      perror("ERROR on binding");
      return EXIT_ERROR;
    }
    dst->conn = conn;

    fdu_listener_connect(dst);
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
int cmu_read(cmu_socket_t *sock, char *dst, int length, int flags)
{
  char *new_buf;
  int read_len = 0;

  if (length < 0)
  {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
    ;

  switch (flags)
  {
  case NO_FLAG:
    while (sock->received_len == 0)
    {
      pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    }
  case NO_WAIT:
    if (sock->received_len > 0)
    {
      if (sock->received_len > length)
        read_len = length;
      else
        read_len = sock->received_len;

      memcpy(dst, sock->received_buf, read_len);
      if (read_len < sock->received_len)
      {
        new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len,
               sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
      }
      else
      {
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
int cmu_write(cmu_socket_t *sock, char *src, int length)
{
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

/*
 * Disconnect from the initiator, which could be either client or server.
 * Param: dst - Destination port
 */

void fdu_initiator_disconnect(cmu_socket_t *dst)
{
  char *rsp;
  //int unchecked_pkt_num,buf_len;
  size_t conn_len = sizeof(dst->conn);

  //Make sure the child thread of the client is over
  dst->connection.disconnect = FIN_WAIT_1;

  //create and send FIN pkt with ack dst->sender->nextseq and seq dst->sender->nextseq
  //rsp = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port), dst->sender->nextseq, dst->sender->nextseq,
  //                      DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);

  while (TRUE)
  {
    rsp = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port), (dst->window.sender)->nextseq, (dst->window.receiver)->expect_seq,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(dst->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(dst->conn), conn_len);
    check_for_data(dst, TIMEOUT);
    if (dst->connection.disconnect == FIN_WAIT_2)
    {
      break;
    }
  }
  free(rsp);

  // wait for the FIN packet from listen
  while (TRUE)
  {
    check_for_data(dst, NO_WAIT);
    if (dst->connection.disconnect == TIME_WAIT)
    {
      break;
    }
  }

  struct timeval current_time;

  // TIME_WAIT check for whether overtime frequently, if overtime then the listen is disconnected
  while (TRUE)
  {
    check_for_data(dst, NO_WAIT);
    gettimeofday(&current_time, NULL);
    // overtime
    if (current_time.tv_sec - dst->timer->start_time.tv_sec > dst->connection.disconnect_time / 1000)
    {
      break;
    }
  }
}

/*
 * Disconnect from the listener, which could be either client or server.
 * Param: sock - the socket used
 */
void fdu_listener_disconnect(cmu_socket_t *sock)
{

  size_t conn_len = sizeof(sock->conn);

  //wait for the FIN pkt from the initiator
  while (TRUE)
  {
    if (sock->connection.disconnect == CLOSE_WAIT)
    {
      break;
    }
    check_for_data(sock, NO_WAIT);
  }

  //create and send FIN pkt with ack dst->sender->nextseq and seq dst->sender->nextseq
  char *rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), sock->window.sender->nextseq, sock->window.sender->nextseq,
                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);

  sock->connection.disconnect = LAST_ACK;

  while (TRUE)
  {
    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(sock->conn), conn_len);
    //check whether timeout or not
    check_for_data(sock, TIMEOUT);
    //if the initiator is "CLOSED" then break
    if (sock->connection.disconnect == CLOSED)
    {
      break;
    }
  }
  free(rsp);
}

/*
  * free the RAM uesd by sock and close the Monitor descriptor
  */
int fdu_free_socket(cmu_socket_t *sock)
{
  if (sock != NULL)
  {
    if (sock->received_buf != NULL)
      free(sock->received_buf);
    if (sock->sending_buf != NULL)
      free(sock->sending_buf);

    if (sock->timer != NULL)
    {
      free(sock->timer);
    }

    if (sock->window.receiver != NULL)
    {
      free(sock->window.receiver);
    }
    if (sock->window.sender != NULL)
    {
      for (int i = 0; i < sock->window.sender->window_size; i++)
      {
        if (sock->window.sender->win_packet_buffer[i] != NULL)
        {
          free(sock->window.sender->win_packet_buffer[i]);
        }
      }
      free(sock->window.sender);
    }
  }
  else
  {
    perror("ERORR Null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

void close_backend(cmu_socket_t *dst)
{

  int unchecked_pkt_num, buf_len;

  while (TRUE)
  {
    while (pthread_mutex_lock(&(dst->window.sender_lock)) != 0)
      ;
    //the num of data pkt unchecked
    unchecked_pkt_num = dst->window.sender->nextseq - dst->window.sender->base;

    while (pthread_mutex_lock(&(dst->send_lock)) != 0)
      ;
    //the length of unsend buffer
    buf_len = dst->sending_len;

    //release the lock
    if (buf_len == 0 && unchecked_pkt_num == 0)
    {
      pthread_mutex_unlock(&(dst->send_lock));
      pthread_mutex_unlock(&(dst->window.sender_lock));
      break;
    }
    pthread_mutex_unlock(&(dst->send_lock));
    pthread_mutex_unlock(&(dst->window.sender_lock));
  }

  while (pthread_mutex_lock(&(dst->death_lock)) != 0)
    ;
  dst->dying = TRUE;
  pthread_mutex_unlock(&(dst->death_lock));

  // terminate another thread
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
int cmu_close(cmu_socket_t *sock)
{
  close_backend(sock);
  // execute 4 wave agreement according to differnt end type
  if (sock->type == TCP_initiator)
    fdu_initiator_disconnect(sock);
  else
    fdu_listener_disconnect(sock);
  return fdu_free_socket(sock);
}
