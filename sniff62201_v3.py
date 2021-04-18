import time
import threading
import iptc
from scapy.all import *
# 明确配置变量
#count = 0 #计时器读秒

#用户字典中的IP对应的值设为 [布尔类型0,计时器秒数1]，用于记录该IP是否被防火墙放行及时间
#初始字典中只有本地地址
user_list={
     '127.0.0.1': [False,0],
  }

def Callback(packet):
    print('src:%s--->dst:%s'%(packet[IP].src, packet[IP].dst))#打印IP
    msg1 = packet[Raw].load #读取数据包的数据内容
    sp = packet[IP].src #读取数据包IP源地址，并存入sp
    user_list[sp]=[False,0]#读取新的数据包地址，添加规则写入字典
    if sp not in user_list.keys(): #查找字典
        print('Illegal account, please try again!')
        return
    elif msg1.decode('utf-8') == 'admin': #判断口令
        print('服务器收到消息:', msg1.decode('utf-8'))
        #count = 0 #重置计时器时间
        user_list[sp][1] = 0
        #启动线程
        thread_admin = threading.Thread(target=delayTime, args=(sp, 1 ,sp))
        thread_admin.start()

#线程函数
def delayTime(threadName, delay, sp):
    if not user_list[sp][0]: #user_list[sp][0],是布尔类型，见user_list字典，sp为正在请求的IP地址
        user_list[sp][0] = True #如果为false（防火墙没有放行该IP，则设置为True，并新建防火墙规则
        #新建规则
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")

        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.src = sp

        match = iptc.Match(rule, "tcp")
        match.dport = "80"
        rule.add_match(match)

        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        chain.insert_rule(rule)
        # chain.delete_rule(rule)
        print("Port 80 is open!")
    else:
        return
    while user_list[sp][1] < 10: #计时器，倒计时10s
        time.sleep(delay)
        user_list[sp][1] += 1
        print("%s: %s-%s" % (threadName, time.ctime(time.time()), user_list[sp][1]))
    print('Port 80 closed !')
    #lst.pop(packet_count)
    chain.delete_rule(rule) #倒计时结束，清除规则
    #httpBool = False
    user_list[sp][0]=False  #设置该IP放行状态布尔为假


while 1:
    # 使用sniff抓包
    print('start sniffing')
    msg1 = sniff(filter='dst port 62201', prn=Callback) #此处程序会等待，直到抓到数据包


# 关闭服务器
print('Sever closed')
