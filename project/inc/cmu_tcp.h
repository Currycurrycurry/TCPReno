#ifndef _CMU_TCP_H_
#define _CMU_TCP_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h> 
#include <unistd.h> 
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "cmu_packet.h"
#include "backend.h"
#include "global.h"
#include "grading.h"



/*
 * DO NOT CHANGE THESE FUNCTION SIGNATURES
 */
int cmu_socket(cmu_socket_t * dst, int flag, int port, char * serverIP);
int cmu_close(cmu_socket_t * sock);
int cmu_read(cmu_socket_t * sock, char* dst, int length, int flags);
int cmu_write(cmu_socket_t * sock, char* src, int length);

int wait_ACK_time_out(cmu_socket_t * sock, uint32_t expect_ack, uint32_t expect_seq);
int wait_FIN_no_wait(cmu_socket_t * sock);
int initator_wait_any_packet_no_wait(cmu_socket_t * sock);
void fdu_initator_disconnect(cmu_socket_t * dst);
void fdu_listener_disconnect(cmu_socket_t * sock);

/*
 * You can add functions below this
 */
 

#endif
