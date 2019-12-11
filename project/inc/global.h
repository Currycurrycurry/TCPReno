#include "grading.h"

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define SIZE32 4
#define SIZE16 2
#define SIZE8 1

#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2

#define TRUE 1
#define FALSE 0

#define DEFAULT_TIMEOUT_SEC 3
#define DEFAULT_TIMEOUT_USEC 0
#define TCP_RTT_SHIFT 3
#define TCP_RTTVAR_SHIFT 2
#define TCP_RTOMIN 1           // 1 microsecond
#define TCP_RTOMAX 20000000    // 20 seconds
#define TCP_DEVIATION_SHIFT 2  // 4*dev

#define MAX_QUEUE_SIZE 32
#define MAX_WND_SIZE (MAX_QUEUE_SIZE * 1375)

#define CONN_NO_WAIT 0
#define FIN_WAIT_1 1
#define FIN_WAIT_2 2
#define LAST_ACK 3
#define TIME_WAIT 4
#define CLOSE_WAIT 5
#define CLOSED 6
#define TIMER_ON 1

#define RCVBUFFER 2222222 //temp value, should be revised later


typedef struct {
  // received_packet_t* head;
  char received[MAX_WND_SIZE];
  char buf[MAX_WND_SIZE];
  uint8_t marked[MAX_WND_SIZE];
  uint32_t expect_seq;
} receiver_window_t;

typedef struct {
  uint16_t window_size;
  uint32_t base;
  uint32_t nextseq;
  uint32_t estmated_rtt;
  void** win_packet_buffer;
  // uint16_t buffer_next;
  int ack_cnt;
  pthread_mutex_t ack_cnt_lock;
  struct timeval send_time;
  struct timeval timeout;
} sender_window_t;

typedef struct {
  uint32_t last_seq_received;
  uint32_t last_ack_received;

  sender_window_t* sender;
  receiver_window_t* receiver;

  pthread_mutex_t sender_lock;
  pthread_mutex_t receiver_lock;

  int ack_cnt;
  pthread_mutex_t ack_lock;

} window_t;

typedef struct {
  struct timeval start_time;
  struct timeval time_out;
  uint8_t state;
} cmu_timer_t;

typedef struct {
  uint32_t expect_seq;
  uint32_t expect_ack;
  uint8_t shakenhands;
  uint8_t disconnect;
  uint16_t disconnect_time;
} connection_t;

#define STATUS_CLOSED 0
#define STATUS_SYN_SENT 1
#define STATUS_ESTABLISHED 2
#define STATUS_FIN_WAIT_1 3
#define STATUS_FIN_WAIT_2 4
#define STATUS_TIME_WAIT 5
#define STATUS_LISTEN 6
#define STATUS_SYN_RCVD 7
#define STATUS_CLOSE_WAIT 8
#define STATUS_LAST_ACK 9

typedef struct {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  uint16_t their_port;
  struct sockaddr_in conn;
  char* received_buf;
  int received_len; //rcvbuffer
  pthread_mutex_t recv_lock;
  pthread_cond_t wait_cond;
  char* sending_buf;
  int sending_len;
  int type;
  pthread_mutex_t send_lock;
  int dying;
  pthread_mutex_t death_lock;
  window_t window;
  cmu_timer_t* timer; 
  connection_t connection;
  int status;
  int syn_seq;
  int rwnd; // for flow control
} cmu_socket_t;

typedef struct {
  long int t_srtt;
  long int t_rttvar;
  struct timeval t_rto;
} cmu_tcpcb;

#endif