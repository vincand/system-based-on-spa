import socket

p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #ipv4 UDP

while 1:
    msg1 = input('please input username:')
    #判别空消息
    if not msg1 :
        continue
    p.sendto(msg1.encode('utf-8'),('192.168.23.131',62201)) #编码utf-8，向server端的62201端口发送udp报文
    if msg1 == 'admin':
        break
p.close()
