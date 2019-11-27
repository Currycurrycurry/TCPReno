#include "grading.h"
#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2

#define TRUE 1
#define FALSE 0


#define TCP_RTT_SHIFT 3
#define TCP_RTTVAR_SHIFT 2
#define TCP_RTOMIN 1 //1 microsecond
#define TCP_RTOMAX 20000000  //20 seconds
#define TCP_DEVIATION_SHIFT 2 //4*dev

#define MAX_WND_SIZE 32
typedef struct {
  uint32_t buf_len;
  uint32_t seq;
  uint32_t ack_waiting_for;
  uint32_t len;
  char* msg;
  int ack_cnt;
  pthread_mutex_t ack_cnt_lock;
  clock_t sent_time;
} pkt_t;

typedef struct {
  pkt_t* queue[MAX_WND_SIZE];
  int siz;
  int front;
  int next;
  int end;
 } pkt_window_t;


typedef struct {
	uint32_t last_seq_received;
	uint32_t last_ack_received;
	// the msg is the full packet with header
	pkt_window_t* send_wnd;
	// note that msg in recv_wnd is raw data
	pkt_window_t* recv_wnd;

	pthread_mutex_t ack_lock;
} window_t;


typedef struct {
	int socket;
	pthread_t thread_id;
	uint16_t my_port;
	uint16_t their_port;
	struct sockaddr_in conn;
	char* received_buf;
	int received_len;
	pthread_mutex_t recv_lock;
	pthread_cond_t wait_cond;
	char* sending_buf;
	int sending_len;
	int type;
	pthread_mutex_t send_lock;
	int dying;
	pthread_mutex_t death_lock;
	window_t window;
} cmu_socket_t;

typedef struct {
    long int t_srtt;
    long int t_rttvar;
    struct timeval t_rto;
} cmu_tcpcb;

#endif