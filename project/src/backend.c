#include "backend.h"

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
  uint32_t data_len, seq;
  socklen_t conn_len = sizeof(sock->conn);
  switch(flags){
    case ACK_FLAG_MASK:
      // no matter what ack number we have received, we won't let it go
      uint32_t ack;
      // TODO: do we need the lock bellow?
      while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
      ack = sock->window.last_ack_received = get_ack(pkt);
      pthread_mutex_unlock(&(sock->window.ack_lock));
      window_mark_receive(sock->window.send_wnd, ack);
      // if(get_ack(pkt) > sock->window.last_ack_received)
      //   sock->window.last_ack_received = get_ack(pkt);
      break;

    // // the following case handles SYNACK packets, not sure if we want to handle it
    // case ACK_FLAG_MASK | SYN_FLAG_MASK:
    //   sock->window.last_ack_received = get_ack(pkt);
    //   sock->window.last_seq_received = get_seq(pkt);
    default:
      seq = get_seq(pkt);
      rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, seq+1, 
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
        &(sock->conn), conn_len);
      free(rsp);

      if(seq > sock->window.last_seq_received || (seq == 0 && 
        sock->window.last_seq_received == 0)){
        
        sock->window.last_seq_received = seq;
        data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
        if(sock->received_buf == NULL){
          sock->received_buf = malloc(data_len);
        }
        else{
          sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
        }
        memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
        sock->received_len += data_len;
      }

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
  time_out.tv_sec = 3;
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

pkt_window_t* create_pkt_window() {
  pkt_window_t* wnd = (pkt_window_t*)malloc(sizeof(pkt_window_t));
  wnd->siz = 0;
  wnd->front = MAX_WND_SIZE - 1;
  wnd->next = 0;
  wnd->end = 0;
  return wnd;
}

int window_full(pkt_window_t* wnd) {
  return wnd->siz == MAX_WND_SIZE;
}

int window_empty(pkt_window_t* wnd) {
  return wnd->siz == 0;
}

int window_add_pkt(pkt_window_t* wnd, pkt_t* pkt) {
  if (window_full(wnd)) {
    return -1;
  }
  wnd->queue[wnd->end] = pkt;
  wnd->end = window_inc(wnd->end);
  wnd->siz++;
}

int window_has_unsent(pkt_window_t* wnd, pkt_t* pkt) {
  if (wnd->next != wnd->end) {
    pkt = wnd->queue[wnd->next];
    wnd->next = window_inc(wnd->next);
    return TRUE;
  }
  pkt = NULL;
  return FALSE;
}

int window_inc(int v) {
  return (v == MAX_WND_SIZE - 1) ? 0 : v + 1;
}

void pkt_free(pkt_t* pkt) {
  free(pkt->msg);
  free(pkt);
}

void window_mark_receive(pkt_window_t* wnd, int ack) {
  // theoritically speaking, binary search can be applied, but for simplicity we'll just iterate through all sent packets
  for (int i = window_inc(wnd->front); i != wnd->next; i = window_inc(i)) {
    if (wnd->queue[i]->ack_waiting_for == ack) {
      wnd->queue[i]->ack_cnt++;
      break;
    }
  }
  while (!window_empty(wnd) && wnd->queue[window_inc(wnd->front)]->ack_cnt > 0) {
    wnd->front = window_inc(wnd->front);
    pkt_free(wnd->queue[wnd->front]);
  }
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
void single_send(cmu_socket_t * sock, char* data, int buf_len){
    char* msg;
    char* data_offset = data;
    int sockfd, plen;
    size_t conn_len = sizeof(sock->conn);
    uint32_t seq, ack;

    // used for tracking the sent packages
    pkt_window_t* wnd = sock->window.send_wnd;
    pkt_t* pkt;
    uint32_t initial_seq, terminal_seq;

    seq = initial_seq = sock->window.last_ack_received;
    // note that ack is the next byte the receiver is waiting for, so the initial seq number is the last ack number
    terminal_seq = initial_seq + buf_len;

    sockfd = sock->socket; 
    if(buf_len > 0){
      // event loop
      while (TRUE) { // in pure C, we don't have boolean type
        // we have more packets to make
        if (!window_full(wnd) && buf_len > 0) {
          pkt = (pkt_t*)malloc(sizeof(pkt_t));
          pkt->buf_len = buf_len;
          pkt->seq = seq;
          if(buf_len <= MAX_DLEN){
            plen = DEFAULT_HEADER_LEN + buf_len;
            msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, buf_len);
            buf_len = 0;
          }
          else{
            plen = DEFAULT_HEADER_LEN + MAX_DLEN;
            msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, MAX_DLEN);
            buf_len -= MAX_DLEN;
          }
          pkt->msg = msg;
          pkt->len = plen;
          pkt->ack_waiting_for = seq + (buf_len - pkt->buf_len);
          window_add_pkt(wnd, pkt);
          data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
        }

        // we have more packets to send
        if (window_has_unsent(wnd, pkt)) {
          assert(pkt != NULL);
          sendto(sockfd, pkt->msg, pkt->len, 0, (struct sockaddr*) &(sock->conn), conn_len);
        }

        // try to receive data
        check_for_data(sock, NO_WAIT);
      }
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

  while(TRUE){
    while(pthread_mutex_lock(&(dst->death_lock)) !=  0);
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
