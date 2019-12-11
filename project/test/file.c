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
        if (sock->received_len > length)
          read_len = length;
        else
          read_len = sock->received_len;

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

/*
 * Disconnect from the initiator, which could be either client or server.
 * Param: dst - Destination port
 */

void fdu_initiator_disconnect(cmu_socket_t *dst) {
  char *rsp;
  // int unchecked_pkt_num,buf_len;
  size_t conn_len = sizeof(dst->conn);

  // Make sure the child thread of the client is over
  dst->connection.disconnect = FIN_WAIT_1;

  // create and send FIN pkt with ack dst->sender->nextseq and seq
  // dst->sender->nextseq rsp = create_packet_buf(dst->my_port,
  // ntohs(dst->conn.sin_port), dst->sender->nextseq, dst->sender->nextseq,
  //                      DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK,
  //                      1, 0, NULL, NULL, 0);

  while (TRUE) {
    rsp = create_packet_buf(
        dst->my_port, ntohs(dst->conn.sin_port), (dst->window.sender)->nextseq,
        (dst->window.receiver)->expect_seq, DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(dst->socket, rsp, DEFAULT_HEADER_LEN, 0,
           (struct sockaddr *)&(dst->conn), conn_len);
    check_for_data(dst, TIMEOUT);
    if (dst->connection.disconnect == FIN_WAIT_2) {
      break;
    }
  }
  free(rsp);

  