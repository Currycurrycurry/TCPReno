#ifndef _CMU_BACK_H_
#define _CMU_BACK_H_
#include "cmu_tcp.h"
#include "global.h"
#include "cmu_packet.h"

int check_ack(cmu_socket_t * dst, uint32_t seq);
void check_for_data(cmu_socket_t * dst, int flags);
void * begin_backend(void * in);
void tcp_xmit_timer(cmu_tcpcb * tp,struct timeval * sent_time);

void send_ACK(cmu_socket_t * sock, uint32_t seq, uint32_t ack);
void start_timer(cmu_timer_t* timer);

void rcv_wnd_cumulative_ack(sender_window_t* wnd,int ack);

#endif
