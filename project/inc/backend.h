#ifndef _CMU_BACK_H_
#define _CMU_BACK_H_
#include "cmu_tcp.h"
#include "global.h"
#include "cmu_packet.h"

int check_ack(cmu_socket_t * dst, uint32_t seq);
void check_for_data(cmu_socket_t * dst, int flags);
void * begin_backend(void * in);
void tcp_xmit_timer(cmu_tcpcb * tp,struct timeval * sent_time);
pkt_window_t* create_pkt_window();
int window_full(pkt_window_t* wnd);
int window_empty(pkt_window_t* wnd);
int window_push_pkt(pkt_window_t* wnd, pkt_t* pkt);
pkt_t* window_has_unsent(pkt_window_t* wnd);
pkt_t* window_front_pkt(pkt_window_t* wnd);
pkt_t* window_pop_pkt(pkt_window_t* wnd);
void window_recv_pkt(pkt_window_t* wnd, pkt_t* pkt);
int window_inc(int v);
void pkt_free(pkt_t* pkt);
void window_mark_receive(pkt_window_t* wnd, int ack);

#endif
