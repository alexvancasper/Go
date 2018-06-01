This is an example of how to send RAW IP packet with UDP and RADIUS CoA-Request in the payload.

<b>syslog_server_db.go</b><br>
The syslog server received the logs on a port 10001 and then parse them and insert it to the database (MySql)
<br>
The example of log message:<br>
The server 10.zxc.1.12 is forwarding the original message from 10.cxz.92.18
<br><i><13>May 30 07:22:21  [2018.05.30-10: 22:57] [10.cxz.92.18] [local7.info] ft_mgr::ft_speed_update: Temperature is not decreasing. Increasing the fan speed.</i>
