#include "backend.h"

void send_ACK(cmu_socket_t *sock, uint32_t seq, uint32_t ack) {
  socklen_t conn_len = sizeof(sock->conn);
  char *rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                                ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
  sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
         (struct sockaddr *)&(sock->conn), conn_len);
  free(rsp);
}

void start_timer(cmu_timer_t *timer) {
  if (timer == NULL) {
    return;
  }
  timer->state = TIMER_ON;
  gettimeofday((struct timeval *)&(timer->start_time), NULL);
}

/*
 * Param: sock - The socket to check for acknowledgements.
 * Param: seq - Sequence number to check
 *
 * Purpose: To tell if a packet (sequence number) has been acknowledged.
 *
 */
int check_ack(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0)
    ;
  if (sock->window.last_ack_received > seq)
    result = TRUE;
  else
    result = FALSE;
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

#define min(a, b) ((a) < (b) ? (a) : (b))
/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void handle_message(cmu_socket_t *sock, char *pkt) {
  char *rsp;
  uint8_t flags = get_flags(pkt);
  uint32_t data_len, seq, ack, rsp_ack;
  socklen_t conn_len;

  // received_payload_t *wnd_pkt;
  receiver_window_t *rcv_wnd = sock->window.receiver;
  sender_window_t *snd_wnd = sock->window.sender;

  conn_len = sizeof(sock->conn);
  data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

  seq = get_seq(pkt);
  ack = get_ack(pkt);

  LOG_INFO("[%c]SYN [%c]ACK [%d]data_len [%d]seq [%d]ack",
           " Y"[(flags & SYN_FLAG_MASK) != 0],
           " Y"[(flags & ACK_FLAG_MASK) != 0], data_len, seq, ack);

  /*
  READTHIS:

  To clarify, for any packet the TCP socket sends, if it is
  * A pure ACK_FLAG_MASK packet, often sent as a response that carries no data.
    The sent seq number does not matter and should be ignored by the receiver,
    and the ack number is the next byte the sender is waiting for.
  * A pure SYN_FLAG_MASK packet, it is assumed to be carrying 1 byte of data,
  even though the payload must be blank. Therefore the receiver should pretend
  it's carrying 1 byte data, and send back a packet with ack number seq + 1.
  SYN_FLAG_MASK is only used for connection management.
  * A SYN_FLAG_MASK | ACK_FLAG_MASK packet. This kind of packet should only be
  used in handshake, where the sender is acknowledging the recieved
  SYN_FLAG_MASK and at the same time telling the other side its own seq number.

  */
  switch (flags) {
    case ACK_FLAG_MASK | SYN_FLAG_MASK:
      LOG_DEBUG("recive SYNACK packet");
      if (ack == sock->syn_seq + 1) {
        sock->window.last_seq_received = seq;
        sock->window.last_ack_received = ack;
        sock->status = STATUS_ESTABLISHED;
      }
      break;
    case SYN_FLAG_MASK:
      LOG_DEBUG("receive SYN packet");
      assert(data_len == 0);
      if (sock->status == STATUS_LISTEN || sock->status == STATUS_SYN_RCVD) {
        seq = get_seq(pkt);
        // create a SNYACK response
        rsp = create_packet_buf(
            sock->my_port, ntohs(sock->conn.sin_port), sock->syn_seq, seq + 1,
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK | ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
        // note that the following send might also get lost, in this case, we
        // still make the status SYN_RCVD. In the future when the initiator
        // retries, we want to still be able to send a SYNACK response.
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
               (struct sockaddr *)&(sock->conn), conn_len);
        sock->status = STATUS_SYN_RCVD;
        sock->window.last_seq_received = seq;
      }
      break;
    case ACK_FLAG_MASK:
      LOG_DEBUG("receive ACK packet");
      if (rand() % 2 != 0) {
        LOG_DEBUG("DROP");
        break;
      }
      // no matter what ack number we have received, we won't let it go
      while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0)
        ;
      sock->window.last_ack_received = ack;
      pthread_mutex_unlock(&(sock->window.ack_lock));
      if (sock->status == STATUS_SYN_RCVD) {
        if (ack == sock->syn_seq + 1) {
          sock->status = STATUS_ESTABLISHED;
        }
      } else {
        if (ack > snd_wnd->base) {
          snd_wnd->base = ack;
          snd_wnd->ack_cnt = 0;
          if (snd_wnd->nextseq > snd_wnd->base) {
            //  start_timer();
            tcp_xmit_timer(&(snd_wnd->tp),&(snd_wnd->send_time));
            if (((snd_wnd->tp.t_rto.tv_sec) > 0) | ((snd_wnd->tp.t_rto.tv_usec) > 0)){
              snd_wnd->timeout=snd_wnd->tp.t_rto;
            }
            gettimeofday((struct timeval *)&(snd_wnd->send_time), NULL);
          }
        } else {
          snd_wnd->ack_cnt++;
        }
      }
      break;
    case FIN_FLAG_MASK:
      // send ACK when recieve FIN
      rsp_ack = get_seq(pkt) + 1;
      seq = get_ack(pkt);
      send_ACK(sock, seq, rsp_ack);
      /*
       * client state:TIME_WAIT, which means client has recieved FIN from server
       * then server send FIN pkt currently
       * thus client must assure terminate until server had recieved AKC
       */
      if (sock->type == TCP_INITATOR &&
          sock->connection.disconnect == TIME_WAIT) {
        start_timer(sock->timer);
        return;
      }
      if (sock->type == TCP_INITATOR &&
          sock->connection.disconnect == FIN_WAIT_2) {
        sock->connection.disconnect = TIME_WAIT;
      }
      if (sock->type == TCP_LISTENER &&
          sock->connection.disconnect == CONN_NO_WAIT) {
        sock->connection.disconnect = CLOSE_WAIT;
      }

      break;

    default:
      LOG_DEBUG("receive payload packet");
      if (rand() % 2 != 0) {
        LOG_DEBUG("DROP");
        break;
      }
      if (sock->status == STATUS_SYN_RCVD) {
        // we are not ready yet, so we pick and check the ack number and discard
        // the payload which will in the future retransmit.
        if (ack == sock->syn_seq + 1) {
          sock->status = STATUS_ESTABLISHED;
        }
      } else {
        // a data packet is received.
        // TODO: for the rcv_wnd/
        if (seq + data_len >= rcv_wnd->expect_seq) {
          // the packet might contain unreceived data
          int i;
          for (i = 0; i < data_len; ++i) {
            int pos = seq + i;
            if (pos >= rcv_wnd->expect_seq &&
                pos < rcv_wnd->expect_seq + MAX_WND_SIZE) {
              rcv_wnd->marked[pos % MAX_WND_SIZE] = 1;
              rcv_wnd->received[pos % MAX_WND_SIZE] =
                  *(pkt + DEFAULT_HEADER_LEN + i);
            }
          }

          for (i = 0; i < MAX_WND_SIZE; ++i) {
            int pos = (i + rcv_wnd->expect_seq) % MAX_WND_SIZE;
            if (rcv_wnd->marked[pos] == 0) {
              break;
            } else {
              rcv_wnd->buf[i] = rcv_wnd->received[pos];
              rcv_wnd->marked[pos] = 0;
            }
          }
          if (i > 0) {
            if (sock->received_buf == NULL) {
              sock->received_buf = malloc(i);
            } else {
              sock->received_buf =
                  realloc(sock->received_buf, sock->received_len + i);
            }
            memcpy(sock->received_buf + sock->received_len, rcv_wnd->buf, i);
            sock->received_len += i;
            rcv_wnd->expect_seq += i;
          }
          ack = rcv_wnd->expect_seq;
        } else {
          ack = seq + data_len;
        }
        rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 0,
                                ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
        LOG_DEBUG("send ACK [%d]ack [%d]expect_seq", ack, rcv_wnd->expect_seq);
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
               (struct sockaddr *)&(sock->conn), conn_len);
        free(rsp);
      }
  }
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket.
 *
 */
void check_for_data(cmu_socket_t *sock, int flags) {
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  fd_set ackFD;
  struct timeval time_out;
  time_out.tv_sec=3;
  time_out.tv_usec=0;
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
    ;
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      LOG_INFO("unblocked");
      break;
    case TIMEOUT:
      FD_ZERO(&ackFD);
      FD_SET(sock->socket, &ackFD);
      if (select(sock->socket + 1, &ackFD, NULL, NULL, &time_out) <= 0) {
        break;
      }
      LOG_DEBUG("timeout");
    case NO_WAIT:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN,
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= DEFAULT_HEADER_LEN) {
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, NO_FLAG,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    char *tmp = (char *)malloc(21);
    memcpy(tmp, pkt, min(20, plen));
    tmp[min(20, plen)] = 0;
    LOG_INFO("received len %ld, plen %d, %s...", len, plen, tmp);
    free(tmp);
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

int timeout(sender_window_t *sender) {
  struct timeval current_time;
  gettimeofday(&current_time, NULL);
  // TODO dynamic time interval
  if (((current_time.tv_sec - sender->send_time.tv_sec) * 1000000L +
       current_time.tv_usec - sender->send_time.tv_usec) >
      sender->timeout.tv_sec * 1000000L + sender->timeout.tv_usec) {
    return TRUE;
  }
  return FALSE;
}

/*
 * Param: sock - The socket to use for sending data
 * Param: data - The data to be sent
 * Param: buf_len - the length of the data being sent
 *
 * Purpose: Breaks up the data into packets and sends a single
 *  packet at a time.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void single_send(cmu_socket_t *sock, char *data, int buf_len) {
  char *msg;
  char *data_offset = data;
  int sockfd, plen;
  size_t conn_len = sizeof(sock->conn);
  uint32_t initial_seq, terminal_seq;
  sender_window_t *wnd;

  // note that we assume the window is already initialized. It is initialized in
  // handshake and after each single_send.
  wnd = sock->window.sender;
  initial_seq = wnd->base;
  // note that ack is the next byte the receiver is waiting for, so the initial
  // seq number is the last ack number terminal_seq = initial_seq + buf_len;
  terminal_seq = initial_seq + buf_len;

  sockfd = sock->socket;
  if (buf_len > 0) {
    // event loop

    gettimeofday(&wnd->send_time, NULL);
    while (TRUE) {  // in pure C, we don't have boolean type
      if (buf_len > 0 && wnd->nextseq < wnd->base + MAX_WND_SIZE) {
        // we have more packets to make & send, the second branch is for flow
        // control
        LOG_DEBUG("[%d]buf_len", buf_len);
        if (buf_len <= MAX_DLEN) {
          plen = DEFAULT_HEADER_LEN + buf_len;
          // TODO ack value set
          msg = create_packet_buf(sock->my_port, sock->their_port, wnd->nextseq,
                                  sock->window.last_seq_received +
                                      1,  // in case the ack packet is lost, and
                                          // handshake not finished
                                  DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL,
                                  data_offset, buf_len);
          buf_len = 0;
        } else {
          plen = DEFAULT_HEADER_LEN + MAX_DLEN;
          msg = create_packet_buf(sock->my_port, sock->their_port, wnd->nextseq,
                                  sock->window.last_seq_received + 1,
                                  DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL,
                                  data_offset, MAX_DLEN);
          buf_len -= MAX_DLEN;
        }
        LOG_DEBUG("[%d]seq sent, [%d]plen", wnd->nextseq, plen);
        wnd->nextseq += plen - DEFAULT_HEADER_LEN;
        data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        free(msg);
        msg = NULL;
      }

      // try to receive data, waiting for ack
      check_for_data(sock, NO_WAIT);

      // timeout retransmit || 3 ack retransmit : (a little revision)
      if (timeout(wnd) || wnd->ack_cnt == 3) {
        int dlen = min(MAX_DLEN, terminal_seq - wnd->base);
        LOG_DEBUG("RESEND [%d]seq [%d]dlen", wnd->base, dlen);
        wnd->ack_cnt = 0;
        gettimeofday(&wnd->send_time, NULL);
        plen = DEFAULT_HEADER_LEN + dlen;  //?
        msg = create_packet_buf(sock->my_port, sock->their_port, wnd->base,
                                sock->window.last_seq_received,
                                DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL,
                                data + wnd->base - initial_seq, dlen);
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
      }
      if (wnd->base == terminal_seq) {
        break;
      }
      // sleep(1);
    }
    wnd->base = terminal_seq;
    wnd->nextseq = terminal_seq;
  }
}

/*
 * Param: tp - the simple implement of tcp control block
 * Param: sent_time - the sent_time in cmu_packet_t which is a time mark helping
 * to calculate current RTT
 *
 * Purpose: using the lastly received packet's sent_time to update t_srtt and
 * t_rttvar, thus generating a new RTO.
 */
void tcp_xmit_timer(cmu_tcpcb *tp, struct timeval *sent_time) {
  struct timeval time_now;
  long int delta;
  gettimeofday(&time_now, NULL);  // get current time
  long int rtt_sec = (time_now.tv_sec) - (sent_time->tv_sec);
  long int rtt_usec =
      rtt_sec * 1000000 + (time_now.tv_usec) -
      (sent_time->tv_usec);  // get rtt time in microsecond precision
  // the RFC793 algorithm
  if ((tp->t_srtt) != 0) {
    delta = rtt_usec - (tp->t_srtt >> TCP_RTT_SHIFT);
    (tp->t_srtt) = (tp->t_srtt) + delta;
    if (delta < 0) delta = -delta;
    delta = delta - (tp->t_rttvar >> TCP_RTTVAR_SHIFT);
    (tp->t_rttvar) = (tp->t_rttvar) + delta;
    long int rtoval =
        ((tp->t_rttvar << TCP_DEVIATION_SHIFT) >> TCP_RTTVAR_SHIFT) +
        (tp->t_srtt >> TCP_RTT_SHIFT);
    if (rtoval < TCP_RTOMIN) rtoval = TCP_RTOMIN;
    if (rtoval > TCP_RTOMAX) rtoval = TCP_RTOMAX;
    if (rtoval >= 1000000) {
      (tp->t_rto).tv_sec = rtoval / 1000000;
      (tp->t_rto).tv_usec = rtoval - ((tp->t_rto).tv_sec) * 1000000;
    } else {
      (tp->t_rto).tv_usec = rtoval;
    }
  } else {
    (tp->t_srtt) = rtt_usec << TCP_RTT_SHIFT;
    (tp->t_rttvar) = rtt_usec << (TCP_RTTVAR_SHIFT - 1);
  }
}

/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side.
 *
 */
void *begin_backend(void *in) {
  LOG_INFO("begin backend");
  cmu_socket_t *dst = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  char *data;

  while (TRUE) {
    while (pthread_mutex_lock(&(dst->death_lock)) != 0)
      ;
    death = dst->dying;
    pthread_mutex_unlock(&(dst->death_lock));

    while (pthread_mutex_lock(&(dst->send_lock)) != 0)
      ;
    buf_len = dst->sending_len;

    if (death && buf_len == 0) break;

    if (buf_len > 0) {
      LOG_INFO("send buffer %d", buf_len);
      data = malloc(buf_len);
      memcpy(data, dst->sending_buf, buf_len);
      dst->sending_len = 0;
      free(dst->sending_buf);
      dst->sending_buf = NULL;
      pthread_mutex_unlock(&(dst->send_lock));
      single_send(dst, data, buf_len);
      LOG_INFO("send finished");
      free(data);
    } else
      pthread_mutex_unlock(&(dst->send_lock));
    check_for_data(dst, NO_WAIT);

    while (pthread_mutex_lock(&(dst->recv_lock)) != 0)
      ;

    if (dst->received_len > 0)
      send_signal = TRUE;
    else
      send_signal = FALSE;
    pthread_mutex_unlock(&(dst->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(dst->wait_cond));
    }
    // sleep(1);
  }

  pthread_exit(NULL);
  return NULL;
}
