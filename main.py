from dnslib import *
from cachetools import Cache, TTLCache
import socket


IP = "127.0.0.1"
socket = socket.socket(type=socket.SOCK_DGRAM)
socket.bind((IP, 53))


Root_Servers_IP =  ("198.41.0.4",
                    "199.9.14.201",
                    "192.33.4.12",
                    "199.7.91.13",
                    "192.203.230.10",
                    "192.5.5.241",
                    "192.112.36.4",
                    "198.97.190.53",
                    "192.36.148.17",
                    "192.58.128.30",
                    "193.0.14.129",
                    "199.7.83.42",
                    "202.12.27.33")


#example of blacklist
Blacklist = ["youtube.com."]


class TTLCacheModified(TTLCache):
    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__, ttl=100):
        super(TTLCacheModified, self).__setitem__(key, value)
        new_link = self._TTLCache__links.get(key, None)
        if new_link:
            new_link.expire += ttl - self.ttl
                


def request(domain, qtype, ip):
    
    q = DNSRecord(q=DNSQuestion(domain, qtype))
    response = DNSRecord.parse(q.send(ip))
    authoritative = response.auth
    additional = response.ar
    
    if response.rr == []:
        for i in additional:
            if i.rtype == 1:
                ip = str(i.rdata)
                return request(domain, qtype, ip)
    else:

        if response.rr[0].rtype == qtype:
            Cache.__setitem__((domain, qtype), response.rr,  ttl=response.rr[0].ttl)
            return response.rr
        


def resolver(domain, qtype):
    
    if (domain, qtype) in Cache:
        return Cache[(domain, qtype)]
    
    else:
        for r_ip in Root_Servers_IP:
            
            q = DNSRecord(q=DNSQuestion(domain, qtype))
            response = DNSRecord.parse(q.send(r_ip))
            if response.ar:
                return request(domain, qtype, r_ip)
    


if __name__ == '__main__':
    
    Cache = TTLCacheModified(maxsize=50, ttl=100)

    try:
        while True:
            packet, addr = socket.recvfrom(1024)
            message = DNSRecord.parse(packet)
            header = message.header
            ans_section = []
        
            if header.qr == 0 and header.rcode == 0:
                for question in message.questions:
                    domain = question.qname
                    qtype = question.qtype
                
                    if domain not in Blacklist:
                        res = resolver(domain, qtype)
                    if res:
                        ans_section += res
                    
                header.qr = 1
                header.ra = 1
                if ans_section == []:
                    header.rcode = 4
                
                answer = DNSRecord(header, message.questions, ans_section)
                socket.sendto(answer.pack(), addr)
    except KeyboardInterrupt:
        socket.close()
        exit(0)
   
