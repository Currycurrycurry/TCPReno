#include "cmu_tcp.h"

typedef struct {
    int port;
    char *ip;
} conn_t;

void* try_listen(void* arg) {
    int err;
    conn_t *conn = (conn_t*)arg;
    cmu_socket_t sock;
    err = cmu_socket(&sock, TCP_LISTENER, conn->port, conn->ip);
    int *ret = (int*)malloc(sizeof(int));
    *ret = err;
    return ret;
}

void* try_initiate(void* arg) {
    int err;
    conn_t *conn = (conn_t*)arg;
    cmu_socket_t sock;
    err = cmu_socket(&sock, TCP_INITATOR, conn->port, conn->ip);
    int *ret = (int*)malloc(sizeof(int));
    *ret = err;
    return ret;
}

int main(int argc, char **argv) {
    pthread_t pl, pi;
    conn_t* conn = (conn_t*)malloc(sizeof(conn_t));
    conn->ip = "0.0.0.0";
    conn->port = 2333;
    pthread_create(&pl, NULL, try_listen, (void*)conn);
    pthread_create(&pi, NULL, try_initiate, (void*)conn);
    int* res1 = (int*)malloc(sizeof(int));
    int* res2 = (int*)malloc(sizeof(int));
    pthread_join(pl, (void**)&res1);
    pthread_join(pi, (void**)&res2);
    if (res1 < 0 || res2 < 0) {
        printf("test error\n");
        return -1;
    }
    return 0;
}