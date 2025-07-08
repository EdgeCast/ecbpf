# XDP_FILTER

This is a proof of concept to filter IP fragments and source drop.
IP fragments destined to a VIP can't be handled properly because
they arrive at different directors.  We have seen customer DDOS
stress tests that also involved sending lots of fragments.

One issue that needs to be resolved is locally destined fragments.
Right now ack fast path contains information about which IPs are
local, but we should see if we can make that generally available.
Perhaps flag a packet as local in the root array using XDP metadata?

The source droping part is a duplication of the PoC firewall
functionality, but based on some recent layer 7 attacks, we added
it here for faster deployment.  We can use source droping from
the firewall in more complex pattern finger prints.

# Testing hints

Using the Vagrant environment in the root of this repo (documented in 
the root `README.md`), you can build and test this filter.


## Buliding

Use `./test.sh -b` to build the filter.

## Attaching

Use `./test.sh -a` to attach to the private interface that connects
the `server` and `client` virtual machines.

```
vagrant@server:/vagrant/xdp_filter$ ./test.sh -a
libecbpf: INFO: Can't stat map path /sys/fs/bpf/enp0s8: No such file or directory
Failed to detach root program on interface enp0s8Root detach done
libbpf: loading ../build/xdp_root/xdp_root_kern.o
libbpf: elf: section(3) xdp_root, size 376, link 0, flags 6, type=1
libbpf: sec 'xdp_root': found program 'xdp_root_prog' at insn offset 0 (0 bytes), code size 47 insns (376 bytes)
libbpf: elf: section(4) .relxdp_root, size 144, link 21, flags 0, type=9
libbpf: elf: section(5) .maps, size 96, link 0, flags 3, type=1
libbpf: elf: section(6) license, size 4, link 0, flags 3, type=1
libbpf: license of ../build/xdp_root/xdp_root_kern.o is APL 
libbpf: elf: section(12) .BTF, size 1214, link 0, flags 0, type=1
```

## Filter Status

```
vagrant@server:/vagrant/xdp_filter$ ./test.sh -s
Current Configuration:

frags_drop? true
ptb_send? true
ptb_max_pps: 200

Drop Maps:


Stats:

eth_frame_err: 0
ip_header_err: 0
ip6_header_err: 0
ip_drop_count: 0
ip6_drop_count: 0
ip_frag_drop_count: 1430
ptb_sent_count: 602
ptb_err_count: 0
```

## Testing Packet Too Big

After attaching the program, `vagrant ssh client` and send some ICMP packets that are
bigger than the MTU.

By default, fragments are not dropped.  Fragment dropping can be enabled using
the `--frags-drop` flag:

```
sudo ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --frags-drop
```

To turn off fragment dropping, use the `--no-drop-flags` flag.

```
sudo ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --no-frags-drop
```

```
vagrant@client:~$ ping -c 2 -s 2048 server
2056 bytes from server (192.168.56.10): icmp_seq=126 ttl=64 time=1.39 ms
2056 bytes from server (192.168.56.10): icmp_seq=127 ttl=64 time=1.97 ms
From server (192.168.56.10) icmp_seq=128 Frag needed and DF set (mtu = 1500)
From server (192.168.56.10) icmp_seq=129 Frag needed and DF set (mtu = 1500)
...
From server (192.168.56.10) icmp_seq=149 Frag needed and DF set (mtu = 1500)
From server (192.168.56.10) icmp_seq=150 Frag needed and DF set (mtu = 1500)
2056 bytes from server (192.168.56.10): icmp_seq=151 ttl=64 time=2.11 ms
2056 bytes from server (192.168.56.10): icmp_seq=152 ttl=64 time=1.14 ms
```


Ping will report receiving the PTB ICMP by default.  These responses
rate limited by default.

```
vagrant@client:~$ ping -c 2 -s 2048 server
PING server (192.168.56.10) 2048(2076) bytes of data.
From server (192.168.56.10) icmp_seq=1 Frag needed and DF set (mtu = 1500)
From server (192.168.56.10) icmp_seq=2 Frag needed and DF set (mtu = 1500)

--- server ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1002ms
```

Just dropping fragments without sending back a PTC message, set the PTB rate to
0 using the `--ptb-max-pps` flag..

```
vagrant@server:/vagrant/xdp_filter$ sudo ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --ptb-max-pps 0
```

This will result in no reply to the fragmented packets.

```
vagrant@client:~$ ping -c 2 -s 2048 server
PING server (192.168.56.10) 2048(2076) bytes of data.

--- server ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1011ms
```


To test rate limiting of the PTB messages, use `ping -f` from the client.

```
vagrant@client:~$ sudo ping -f -s 2048 server
PING server (192.168.56.10) 2048(2076) bytes of data.
EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE.........................................................EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE.EEEEEEE.......................................................EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE.^C
--- server ping statistics ---
713 packets transmitted, 0 received, +600 errors, 100% packet loss, time 2107ms
pipe 2
```

## Testing the "evil bit"

Recent versions of nping support setting the "evil bit".  You may have to build from source.

```
vagrant@client:~$ sudo nping --evil --icmp --icmp-type time server
    
Starting Nping 0.7.94 ( https://nmap.org/nping ) at 2023-09-06 18:04 UTC
SENT (0.0187s) ICMP [192.168.56.20 > 192.168.56.10 Timestamp request (type=13/code=0) id=45910 seq=1 orig=0 recv=0 trans=0] IP [ttl=64 id=5394 iplen=40 ]
SENT (1.0225s) ICMP [192.168.56.20 > 192.168.56.10 Timestamp request (type=13/code=0) id=45910 seq=2 orig=0 recv=0 trans=0] IP [ttl=64 id=5394 iplen=40 ]
SENT (2.0256s) ICMP [192.168.56.20 > 192.168.56.10 Timestamp request (type=13/code=0) id=45910 seq=3 orig=0 recv=0 trans=0] IP [ttl=64 id=5394 iplen=40 ]
SENT (3.0303s) ICMP [192.168.56.20 > 192.168.56.10 Timestamp request (type=13/code=0) id=45910 seq=4 orig=0 recv=0 trans=0] IP [ttl=64 id=5394 iplen=40 ]
SENT (4.0337s) ICMP [192.168.56.20 > 192.168.56.10 Timestamp request (type=13/code=0) id=45910 seq=5 orig=0 recv=0 trans=0] IP [ttl=64 id=5394 iplen=40 ]

Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 5 (200B) | Rcvd: 0 (0B) | Lost: 5 (100.00%)
Nping done: 1 IP address pinged in 5.07 seconds
```

## Testing Payload Size

Non-multiple of 8 or < 8 payloads don't get back a PTB response:

```
vagrant@client:~/nmap-7.94$ sudo nping -c 1 --mf --icmp --icmp-type echo --data-length 7 server 

Starting Nping 0.7.94 ( https://nmap.org/nping ) at 2023-09-20 00:59 UTC
SENT (0.0187s) ICMP [192.168.56.20 > 192.168.56.10 Echo request (type=8/code=0) id=45392 seq=1] IP [ttl=64 id=34644 iplen=35 frag offset=0+ ]
 
Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 1 (35B) | Rcvd: 0 (0B) | Lost: 1 (100.00%)
Nping done: 1 IP address pinged in 1.05 seconds
vagrant@client:~/nmap-7.94$ sudo nping -c 1 --mf --icmp --icmp-type echo --data-length 70 server 

Starting Nping 0.7.94 ( https://nmap.org/nping ) at 2023-09-20 00:59 UTC
SENT (0.0180s) ICMP [192.168.56.20 > 192.168.56.10 Echo request (type=8/code=0) id=55916 seq=1] IP [ttl=64 id=60793 iplen=98 frag offset=0+ ]
 
Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 1 (98B) | Rcvd: 0 (0B) | Lost: 1 (100.00%)
Nping done: 1 IP address pinged in 1.05 seconds

```

Modulo 8 will get a PTB response:

```
vagrant@client:~/nmap-7.94$ sudo nping -c 1 --mf --icmp --icmp-type echo --data-length 80 server 

Starting Nping 0.7.94 ( https://nmap.org/nping ) at 2023-09-20 00:58 UTC
SENT (0.0232s) ICMP [192.168.56.20 > 192.168.56.10 Echo request (type=8/code=0) id=53202 seq=1] IP [ttl=64 id=60431 iplen=108 frag offset=0+ ]
RCVD (0.0241s) ICMP [192.168.56.10 > 192.168.56.20 Fragmentation required (type=3/code=4) Next-Hop-MTU=108] IP [ttl=128 id=0 iplen=56 ]
 
Max rtt: 0.771ms | Min rtt: 0.771ms | Avg rtt: 0.771ms
Raw packets sent: 1 (108B) | Rcvd: 1 (56B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.05 seconds
vagrant@client:~/nmap-7.94$ sudo nping -c 1 --mf --icmp --icmp-type echo --data-length 8 server 

Starting Nping 0.7.94 ( https://nmap.org/nping ) at 2023-09-20 00:58 UTC
SENT (0.0192s) ICMP [192.168.56.20 > 192.168.56.10 Echo request (type=8/code=0) id=34219 seq=1] IP [ttl=64 id=51609 iplen=36 frag offset=0+ ]
RCVD (0.0209s) ICMP [192.168.56.10 > 192.168.56.20 Fragmentation required (type=3/code=4) Next-Hop-MTU=46] IP [ttl=128 id=0 iplen=56 ]
 
Max rtt: 1.418ms | Min rtt: 1.418ms | Avg rtt: 1.418ms
Raw packets sent: 1 (36B) | Rcvd: 1 (56B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.05 seconds
```

## Testing source IP blackhole

Some preconfigured drop rules for the Vagrant environment can be 
loaded by using `./test.sh -D`

```
vagrant@server:/vagrant/xdp_filter$ ./test.sh -D
Adding 56 subnet tag to address 192.168.56.20/24
Adding 66 subnet tag to address 192.168.66.20/24
```

Check the stats before sending traffic:

```
vagrant@server:/vagrant/xdp_filter$ ./test.sh -s
Current Configuration:

frags_drop? true
ptb_send? true
ptb_max_pps: 200

Drop Maps:

Address: 192.168.56.20/24	Tag: 56 subnet
Address: 192.168.66.20/24	Tag: 66 subnet

Stats:

eth_frame_err: 0
ip_header_err: 0
ip6_header_err: 0
ip_drop_count: 0
ip6_drop_count: 0
ip_frag_drop_count: 1430
ptb_sent_count: 602
ptb_err_count: 0
```

Log into the `client` vagrant and send some traffic to the server.
There should be no response.

```
vagrant@client:~$ ping server
PING server (192.168.56.10) 56(84) bytes of data.
^C
--- server ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1014ms
```

Verify that two packets were dropped by checking the `ip_drop_count`
stats on the `server` again.

```
vagrant@server:/vagrant/xdp_filter$ ./test.sh -s
Current Configuration:

frags_drop? true
ptb_send? true
ptb_max_pps: 200

Drop Maps:

Address: 192.168.56.20/24	Tag: 56 subnet
Address: 192.168.66.20/24	Tag: 66 subnet

Stats:

eth_frame_err: 0
ip_header_err: 0
ip6_header_err: 0
ip_drop_count: 2
ip6_drop_count: 0
ip_frag_drop_count: 1430
ptb_sent_count: 602
ptb_err_count: 0
```

### Clearing the source drops

To clear all source IPs to be dropped, use the `--clear` flag.

```
vagrant@server:/vagrant/xdp_filter$ ./test.sh -D
Adding 56 subnet tag to address 192.168.56.0/24
Adding 66 subnet tag to address 192.168.66.0/24
Adding /64 v6 tag to address 2606:2800:3::/64
Adding /48 v6 tag to address 2606:2800:3::/48
vagrant@server:/vagrant/xdp_filter$ sudo ${BUILD_PATH}/xdp_filter/xdp_filter  --interface ${INTERFACE} --clear
Clearing IPv4 trie.
Clearing IPv6 trie.
vagrant@server:/vagrant/xdp_filter$ ./test.sh -s
Current Configuration:

frags_drop? true
ptb_send? false
ptb_max_pps: 0

Drop Maps:


Stats:

eth_frame_err: 0
ip_header_err: 0
ip6_header_err: 0
ip_drop_count: 0
ip6_drop_count: 0
ip_frag_drop_count: 54
ptb_sent_count: 25
ptb_err_count: 0
```

# Clickhouse

## Getting the distribution of fragment lengths

```
:) select pkt_length, count(*) from sdi.xdp where fragment=1 group by pkt_length into outfile 'frag_lens' format CSV;

SELECT
    pkt_length,
    count(*)
FROM sdi.xdp
WHERE fragment = 1
GROUP BY pkt_length
INTO OUTFILE 'frag_lens'
FORMAT CSV

Query id: 8ca376a6-f5a1-4c96-8f4c-2ef630cefdff


1154 rows in set. Elapsed: 3.071 sec. Processed 319.69 billion rows, 320.33 GB (104.09 billion rows/s., 104.30 GB/s.)
```
