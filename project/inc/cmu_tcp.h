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
#include <assert.h>
#include "cmu_packet.h"
#include "backend.h"
#include "global.h"
#include "grading.h"
#include "macrologger.h"



/*
 * DO NOT CHANGE THESE FUNCTION SIGNATURES
 */
int cmu_socket(cmu_socket_t * dst, int flag, int port, char * serverIP);
int cmu_close(cmu_socket_t * sock);
int cmu_read(cmu_socket_t * sock, char* dst, int length, int flags);
int cmu_write(cmu_socket_t * sock, char* src, int length);


/*
 * You can add functions below this
 */

void fdu_initiator_disconnect(cmu_socket_t * dst);
void fdu_listener_disconnect(cmu_socket_t * sock);
int fdu_free_socket(cmu_socket_t * sock);
void close_backend(cmu_socket_t * dst);

int fdu_initiator_connect(cmu_socket_t* dst);
int fdu_listener_connect(cmu_socket_t* sock);





 

#endif