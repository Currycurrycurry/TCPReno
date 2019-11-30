#include "backend.h"

void send_ACK(cmu_socket_t * sock, uint32_t seq, uint32_t ack) {
  socklen_t conn_len = sizeof(sock->conn);
  char* rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, ack,
                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
  sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)&(sock->conn), conn_len);
  free(rsp);
}



void start_timer(cmu_timer_t* timer) {
    if (timer==NULL) {
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
int check_ack(cmu_socket_t * sock, uint32_t seq){
  int result;
  while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
  if(sock->window.last_ack_received > seq)
    result = TRUE;
  else
    result = FALSE;
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}


#define min(a,b) ((a)<(b)?(a):(b))
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
void handle_message(cmu_socket_t * sock, char* pkt){
  char* rsp;
  uint8_t flags = get_flags(pkt);
  uint32_t data_len, seq, ack;
  uint32_t rsp_ack  = sock->window.last_seq_received;
  socklen_t conn_len = sizeof(sock->conn);

  rcv_pkt_t* wnd_pkt;
  rcv_window_t* rcv_wnd = sock->window.receiver;


  switch(flags) {
    case ACK_FLAG_MASK:
      // no matter what ack number we have received, we won't let it go
      while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
      ack = sock->window.last_ack_received = get_ack(pkt);
      pthread_mutex_unlock(&(sock->window.ack_lock));
      // window_mark_receive(sock->window.send_wnd, ack);
      rcv_wnd_cumulative_ack(sock->window.sender,ack);
      // if(get_ack(pkt) > sock->window.last_ack_received)
      //   sock->window.last_ack_received = get_ack(pkt);
      break;

    // // the following case handles SYNACK packets, not sure if we want to handle it
    // case ACK_FLAG_MASK | SYN_FLAG_MASK:
    //   sock->window.last_ack_received = get_ack(pkt);
    //   sock->window.last_seq_received = get_seq(pkt);

    case FIN_FLAG_MASK:
      //send ACK when recieve FIN
          rsp_ack = get_seq(pkt) + 1;
          seq = get_ack(pkt);
          send_ACK(sock,seq, rsp_ack);
          /*
           * client state:TIME_WAIT, which means client has recieved FIN from server
           * then server send FIN pkt currently
           * thus client must assure terminate until server had recieved AKC
           */
          if(sock->type == TCP_INITATOR && sock->connection.disconnect == TIME_WAIT){
            start_timer(sock->timer);
            return;
          }
          if(sock->type == TCP_INITATOR && sock->connection.disconnect == FIN_WAIT_2) {
            sock->connection.disconnect = TIME_WAIT;
          }
          if(sock->type == TCP_LISTENER && sock->connection.disconnect == CONN_NO_WAIT) {
            sock->connection.disconnect = CLOSE_WAIT;
          }

          break;
    
    default:
      seq = get_seq(pkt);
     

  
      // TODO: for the rcv_wnd 
      if (window_empty(rcv_wnd) || (seq > window_front_pkt(rcv_wnd)->seq)) {
        wnd_pkt = (rcv_pkt_t*)malloc(sizeof(rcv_pkt_t));
        data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
        wnd_pkt->len = data_len;
        wnd_pkt->payload = malloc(data_len);
        wnd_pkt->seq = seq;
        memcpy(wnd_pkt->payload, pkt + DEFAULT_HEADER_LEN, wnd_pkt->len);
        window_recv_pkt(sock->window.receiver, wnd_pkt);
        while (!window_empty(rcv_wnd) && rcv_wnd->queue[window_inc(rcv_wnd->front)]->seq == rsp_ack) {
          wnd_pkt = window_pop_pkt(rcv_wnd);
          if (sock->received_buf == NULL) {
            sock->received_buf = malloc(data_len);
          } else {
            sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
          }
          memcpy(sock->received_buf + sock->received_len, wnd_pkt->payload, data_len);
          sock->received_len += data_len;
          rsp_ack += data_len;
          pkt_free(wnd_pkt);
          wnd_pkt = NULL;
        }
      }
       ack = seq+data_len;
       // TODO: the respond seq number should be the initial seq number
      rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, min(rsp_ack,ack),
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
        &(sock->conn), conn_len);
      free(rsp);



      break;
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
void check_for_data(cmu_socket_t * sock, int flags){
  char hdr[DEFAULT_HEADER_LEN];
  char* pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  fd_set ackFD;
  struct timeval time_out;
  time_out.tv_sec = 3; //TODO (Zhou ) merge the dynamic value
  time_out.tv_usec = 0;


  while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
  switch(flags){
    case NO_FLAG:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
                (struct sockaddr *) &(sock->conn), &conn_len);
      break;
    case TIMEOUT:
      FD_ZERO(&ackFD);
      FD_SET(sock->socket, &ackFD);
      if(select(sock->socket+1, &ackFD, NULL, NULL, &time_out) <= 0){
        break;
      }
    case NO_WAIT:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
               (struct sockaddr *) &(sock->conn), &conn_len);
      break;
    default:
      perror("ERROR unknown flag");



  }
  if(len >= DEFAULT_HEADER_LEN){
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while(buf_size < plen ){
        n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 
          NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

rcv_window_t* create_pkt_window() {
  rcv_window_t* wnd = (rcv_window_t*)malloc(sizeof(rcv_window_t));
  wnd->siz = 0;
  wnd->front = MAX_WND_SIZE - 1; // front is index before the first sent packet
  wnd->next = 0; // next is the next available unsent packet
  wnd->end = 0; // end is the index of the last element in the queue
  // wnd->rcvBuffer_len = 
  return wnd;
}

int window_full(rcv_window_t* wnd) {
  return wnd->siz == MAX_WND_SIZE;
}

int window_empty(rcv_window_t* wnd) {
  return wnd->siz == 0;
}

int window_push_pkt(rcv_window_t* wnd, rcv_pkt_t* pkt) {
  if (window_full(wnd)) {
    return -1;
  }
  wnd->queue[wnd->end] = pkt;
  wnd->end = window_inc(wnd->end);
  wnd->siz++;
  return 0;
}

rcv_pkt_t* window_pop_pkt(rcv_window_t* wnd) {
  rcv_pkt_t* ret;
  if (window_empty(wnd)) {
    return NULL;
  }
  wnd->front = window_inc(wnd->front);
  ret = wnd->queue[wnd->front];
  wnd->queue[wnd->front] = NULL;
  wnd->siz--;
  return ret;
}


// pkt_t* window_has_unsent(pkt_window_t* wnd) {
//   pkt_t* pkt;
//   if (wnd->next != wnd->end) {
//     pkt = wnd->queue[wnd->next];
//     wnd->next = window_inc(wnd->next);
//   } else {
//     pkt = NULL;
//   }
//   return pkt;
// }

int window_inc(int v) {
  return (v == MAX_WND_SIZE - 1) ? 0 : v + 1;
}

rcv_pkt_t* window_front_pkt(rcv_window_t* wnd) {
  if (window_empty(wnd)) {
    return NULL;
  }
  return wnd->queue[window_inc(wnd->front)];
}

void pkt_free(rcv_pkt_t* pkt) {
  free(pkt->payload);
  free(pkt);
}

/**
 * @brief window_recv_pkt inserts one received packet into the recv_wnd of this socket in
 * the order of seq number, it discards packets out of window.
 * 
 * @param wnd the wnd_recv of the socket
 * @param pkt the packet received
 */
void window_recv_pkt(rcv_window_t* wnd, rcv_pkt_t* pkt) {
  rcv_pkt_t* tmp;
  for (int i = window_inc(wnd->front); i != wnd->end; i = window_inc(i)) {
    if (wnd->queue[i]->seq > pkt->seq) {
      do {
        tmp = wnd->queue[i];
        wnd->queue[i] = pkt;
        pkt = tmp;
        i = window_inc(i);
      } while (i != wnd->end);
      break;
    }
  }
  if (!window_full(wnd)) {
    window_push_pkt(wnd, pkt);
  }
}



/**
 * window_mark_receive marks one parket has been successfully received
 */
// void window_mark_receive(pkt_window_t* wnd, int ack) {
//   // theoritically speaking, binary search can be applied, but for simplicity we'll just iterate through all sent packets
//   for (int i = window_inc(wnd->front); i != wnd->next; i = window_inc(i)) {
//     pthread_mutex_init(&wnd->queue[i]->ack_cnt_lock, NULL); 
//     while(pthread_mutex_lock(&wnd->queue[i]->ack_cnt_lock)!=0);
//     wnd->queue[i]->ack_cnt++;
//     pthread_mutex_unlock(&wnd->queue[i]->ack_cnt_lock);
   
//     if (wnd->queue[i]->ack_waiting_for == ack) {
//       break;
//     }
//   }
//   while (!window_empty(wnd) && wnd->queue[window_inc(wnd->front)]->ack_cnt > 0) {
//     window_pop_pkt(wnd);
//   }
// }

void rcv_wnd_cumulative_ack(sender_window_t* wnd,int ack){
  if(ack > wnd->base){
    wnd->base = ack;
    wnd->ack_cnt = 0;
    if(wnd->nextseq>wnd->base){
        //  start_timer();
        gettimeofday((struct timeval *)&(wnd->send_time), NULL);
    }else{
      wnd->ack_cnt++;
    }
  }

}



#define TIMEOUT_INTERVAL 3

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


int timeout(struct timeval send_time){
  struct timeval current_time;
  gettimeofday(&current_time,NULL);
  // TODO dynamic time interval
  if(current_time.tv_sec-send_time.tv_sec > TIMEOUT_INTERVAL){
    return TRUE;
  }
  return FALSE;
    
}
void single_send(cmu_socket_t * sock, char* data, int buf_len){
    char* msg;
    char* data_offset = data;
    int sockfd, plen;
    size_t conn_len = sizeof(sock->conn);
    uint32_t initial_seq;
    sender_window_t* wnd;;
    wnd = sock->window.sender = (sender_window_t*)malloc(sizeof(sender_window_t));
    
    // used for tracking the sent packages
    //initialize the sender window
    wnd->base = sock->window.last_ack_received; //?  
    wnd->nextseq = wnd->base;
    
    
    // pkt_t* pkt;
    // uint32_t initial_seq, terminal_seq;

    initial_seq =  sock->window.last_ack_received;
    // note that ack is the next byte the receiver is waiting for, so the initial seq number is the last ack number
    // terminal_seq = initial_seq + buf_len;

    sockfd = sock->socket; 
    if(buf_len > 0){
      // event loop

      while (TRUE) { // in pure C, we don't have boolean type
        // we have more packets to make & send
        if (buf_len > 0 && wnd->nextseq<wnd->base+MAX_WND_SIZE) {
          if(buf_len <= MAX_DLEN){
            plen = DEFAULT_HEADER_LEN + buf_len;
            //TODO ack value set 
            msg = create_packet_buf(sock->my_port, sock->their_port, wnd->nextseq, sock->window.last_seq_received, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, buf_len);
            buf_len = 0;
          }
          else{
            plen = DEFAULT_HEADER_LEN + MAX_DLEN;
            msg = create_packet_buf(sock->my_port, sock->their_port, wnd->nextseq, sock->window.last_seq_received, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, MAX_DLEN);
            buf_len -= MAX_DLEN;
          }
          wnd->nextseq += plen - DEFAULT_HEADER_LEN;
          data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
          sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);
          free(msg);
          msg = NULL;
        }


        // try to receive data
        check_for_data(sock, NO_WAIT);

        // timeout retransmit || 3 ack retransmit : (a little revision)
        if(timeout(wnd->send_time) || wnd->ack_cnt==3){
          wnd->ack_cnt = 0;
          plen = DEFAULT_HEADER_LEN + MAX_DLEN;//?
          msg = create_packet_buf(sock->my_port, sock->their_port, wnd->base, sock->window.last_seq_received, 
      DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data + wnd->base - initial_seq, MAX_DLEN);
          sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);
        }
      }
    }
}

/*
 * Param: tp - the simple implement of tcp control block
 * Param: sent_time - the sent_time in cmu_packet_t which is a time mark helping to calculate current RTT
 *
 * Purpose: using the lastly received packet's sent_time to update t_srtt and t_rttvar, thus generating a new RTO.
 */
void tcp_xmit_timer(cmu_tcpcb* tp,struct timeval* sent_time){
    struct timeval time_now;
    long int delta;
    gettimeofday(&time_now, NULL);//get current time
    long int rtt_sec=(time_now.tv_sec)-(sent_time->tv_sec);
    long int rtt_usec=rtt_sec*1000000+(time_now.tv_usec)-(sent_time->tv_usec);//get rtt time in microsecond precision
    //the RFC793 algorithm
    if((tp->t_srtt)!=0){
        delta=rtt_usec-(tp->t_srtt>>TCP_RTT_SHIFT);
        (tp->t_srtt)=(tp->t_srtt)+delta;
        if(delta<0)delta=-delta;
        delta=delta-(tp->t_rttvar>>TCP_RTTVAR_SHIFT);
        (tp->t_rttvar)=(tp->t_rttvar)+delta;
        long int rtoval=((tp->t_rttvar<<TCP_DEVIATION_SHIFT)>>TCP_RTTVAR_SHIFT)+(tp->t_srtt>>TCP_RTT_SHIFT);
        if(rtoval<TCP_RTOMIN) rtoval=TCP_RTOMIN;
        if(rtoval>TCP_RTOMAX) rtoval=TCP_RTOMAX;
        if(rtoval>=1000000){
            (tp->t_rto).tv_sec=rtoval/1000000;
            (tp->t_rto).tv_usec=rtoval-((tp->t_rto).tv_sec)*1000000;
        }else{
            (tp->t_rto).tv_usec=rtoval;
        }
        // printf("%u:%u\n",(tp->t_rto));
        printf("%ld:%ld\n",tp->t_rto.tv_sec,tp->t_rto.tv_usec);
    }else{
        (tp->t_srtt) = rtt_usec << TCP_RTT_SHIFT;
        (tp->t_rttvar) = rtt_usec << (TCP_RTTVAR_SHIFT-1);
    }
}

/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side. 
 *
 */
void* begin_backend(void * in){
  cmu_socket_t * dst = (cmu_socket_t *) in;
  int death, buf_len, send_signal;
  char* data;

  while (TRUE) {
    while (pthread_mutex_lock(&(dst->death_lock)) !=  0);
    death = dst->dying;
    pthread_mutex_unlock(&(dst->death_lock));
    
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len;

    if(death && buf_len == 0)
      break;

    if(buf_len > 0){
      data = malloc(buf_len);
      memcpy(data, dst->sending_buf, buf_len);
      dst->sending_len = 0;
      free(dst->sending_buf);
      dst->sending_buf = NULL;
      pthread_mutex_unlock(&(dst->send_lock));
      single_send(dst, data, buf_len);
      free(data);
    }
    else
      pthread_mutex_unlock(&(dst->send_lock));
    check_for_data(dst, NO_WAIT);
    
    while(pthread_mutex_lock(&(dst->recv_lock)) != 0);
    
    if(dst->received_len > 0)
      send_signal = TRUE;
    else
      send_signal = FALSE;
    pthread_mutex_unlock(&(dst->recv_lock));
    
    if(send_signal){
      pthread_cond_signal(&(dst->wait_cond));  
    }
  }


  pthread_exit(NULL); 
  return NULL; 
}


