# Project Documentation : TCP Reno

## 分工说明

- 17302010063 黄佳妮
- author2
- author3
- author4


## 模块说明

### TCP三次握手实现

### TCP四次挥手实现

​        TCP为全双工连接，必须从client和server两端单独进行关闭，下方图片展示了从客户端主动发起挥手关闭tcp连接的过程。

![tcpwave.png](./assets/tcpwave.png)

**实现过程中主要实现的状态标识释义：**

STATUS ESTABLISHED: 无论client端还是server端在握手建立起来之后的稳定状态，也即挥手过程所基于的初始状态；

STATUS FIN WAIT 1：挥手发起方在发送FIN包后所进入的状态，此时等待被动方的ACK pkt，等不到则循环发送FIN包；

STATUS FIN WAIT 2： 挥手发起方在接收到被动方传送的ACK pkt后进入此状态，等待被动方发送FIN，同时仍可接收数据；

STATUS CLOSE WAIT： 挥手被动方接收到FIN包后进入此状态，此时仍可发送数据；

STATUS LAST ACK： 挥手被动方在发送出FIN包后进入此状态，意为等待接收发起方发出的确认ACK；

STATUS TIME WAIT： 挥手发起方在接收到FIN包并发出ACK后转入此状态，此后持续发送ACK，并记录时间，当时长到达2MSL后断开连接；

STATUS CLOSED： 挥手发起方和被动方在完成四次挥手动作后断开连接，进入此状态。

**四次挥手过程简述（以client主动发起为例）：**

​      client没有数据传输和其他需要时，向server主动发起一个FIN pkt，并且是循环发送，状态转入STATUS FIN WAIT 1，而server在收到FIN后也由原来的STATUS ESTABLISHED转入STATUS CLOSE WAIT，并且回复一个ACK，client在收到这个ack后转入STATUS FIN WAIT 2，此后如果server尚有数据需要发送，仍可继续，client也会接收，并会回复ack。而后当server传输完成后即可发送FIN断开，状态转入STATUS LAST ACK，此时client接收到FIN，随即转入STATUS TIME WAIT，并回复ack，在等待2MSL后自行断开连接，转入STATUS CLOSED，server在接收到ack后状态也会转为STATUS CLOSED，超时断开。

在server主动发起挥手时的实现如下：

​        首先，server进入第一个拥塞，向 client循环发送FIN pkt，等待client接收到FIN并回复ack后，跳出第一个拥塞状态，进入第二个等待client发送的FIN的拥塞，直到接收到这个FIN后，进入正常的四次挥手状态。

​       本设计中挥手的实现，除了部分handle_message()中对于FIN包的检测之外，基本独立于chech_for_data()和handle_message()两个函数，以cmu_close()、fdu_initiator_disconnect()、fdu_listener_disconnect()三个函数为主体，实现了线程关闭（close_backend()）和内存资源释放（free_cmu_socket()），自主实现ack的限时检测、等待FIN包接收等函数。

### TCP流量控制实现

#### 从停等协议到滑窗协议

#### rwnd变量添加

### TCP拥塞控制实现


### TCP RTO计算

