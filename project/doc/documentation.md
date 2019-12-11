# Project Documentation : TCP Reno

## 分工说明

- 17302010063 黄佳妮
- author2
- author3
- author4


## 模块说明

### TCP三次握手实现


### TCP四次挥手实现


### TCP流量控制实现


### TCP拥塞控制实现

### RTO Estimation

​	本次lab中，实现了 Jacobson/Karels Algorithm。在"Congestion Avoidance and Control"一文中，我们可以详细地了解到Van Jacobson认为，相较于旧算法粗糙的将RTT指数加权移动平均(EWMA)后再乘以一个系数$\beta$ 来得到RTO，新算法还计算了一个RTT的方差，并通过$RTO=EstimatedRTT+4*DevRTT$来计算得到一个较为精准的RTO数值。此外，相较于时间复杂度高的方差计算，论文中推荐使用RTT的算数平均偏差值mdev来进行一个替代。以下为具体的算法，其中m为RTT时间，Err为误差，a为EstimatedRTT，v为DevRTT。
$$
Err\equiv m−a \\
a \leftarrow a+gErr\\
v\leftarrow v+g(|Err|−v)\\
rto\leftarrow a+4*v
$$
​	论文中推荐g值为0.125不仅方便了位移运算，而且还能模拟出较优的RTO解。

​	伪代码实现如下：

```c
/*update Average estimator */
m −= (sa >> 3);
sa += m;
/* update Deviation estimator */
if (m < 0)
m = −m;
m −= (sv >> 3);
sv += m;
m −= (sa >> 3);
sa += m;
if (m < 0)
m = −m;
m −= (sv >> 2);
sv += m;
rto = (sa >> 3) + sv;
```

​	上述所有的值都将在cmu_tcpcb这一结构体中被维护，每次收到一个ack包后，都将利用ack包中的时间戳，通过tcp_xmit_timer()这一个函数来获得该包的RTT，并且更新RTO时间。