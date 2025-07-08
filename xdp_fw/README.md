# XDP Firewall PoC

This firewall is still in the proof of concept phase.  The goal is to
have something up front in XDP to handle DDOS attacks, not to
implement general packet filtering.

The PoC can be run against pcap files.  Refer to `test.sh` for an
example of running the PoC.

The implementation of the firewall was inspired by:

[eBPF / XDP based firewall and packet filtering](http://vger.kernel.org/lpc_net2018_talks/ebpf-firewall-paper-LPC.pdf)

# Rules

Refer to `parse.y` for the grammar, which is fairly simple.  All
rules are drop rules.  The basic format is packet selectors, ip level
selectors, then [tcp|udp|icmp] selectors. Selectors that are not used are
explictly wildcarded instead of being omitted.  Although it is
possible to combine multiple protocols into the same rule, it is not
implemented.

Some example rules:

```
packet length 123 ip dst any ttl any tcp window 64240
packet length any ip dst any ttl 23 udp dport 53
packet length any ip dst 172.217.4.164 ttl any icmp type 8
```

Rules are stored in BPF array maps for 8/16 bit values.  The index
for these maps is the parameter supplied to the selector.  The value
a index references is a 64 bit integer.  Each set bit in this integer
represents a matching rule.  If the second rule in the ruleset has
an ip ttl selector with a value of 23, the second bit of the value
for the index `23` in the `xdp_fw_ip_ttl_rules` hash map will be set
to 1.

If a selector is any, all possible indexs will be have the rule
enabled if it is a 8/16bits (say, IP TTL).  Or if it is an IP address,
the prefix 0 rule set will be updated.

When processing incoming packets these wildcard rules are logically ored
with any specific rule matches.

As the packet is processed, these rules are logically anded with
previous matches.  If we reach a point where there are no matches, we
return XDP_PASS.  If we however terminate processing with matches,
XDP_DROP is returned.

## Rule matching

Only a small subset of match types have been implemented for this PoC.
We probably want to tune this for DDOS defense so that we avoid
unnecessary map lookups.

* Packet level: Length of packet
* IP level: TTL, IPv4 destination address
* TCP level: Window
* UDP level: destination port
* ICMP level: message type

## Updates

Because rules are spread out among multiple maps, changing the rules involves
unloading the firewall, reading in the new rules, and then reattaching the firewall
to the root array.  This is to prevent a race condition where a rule is present in
part of the maps but not all.  Since the xdp firewall is geared towards DDOS defense,
this is a design trade off (see Inplace Updates below) to keep rule management simple.

For example, in the test environment, you change `--attach` to `--update` to load
a new set of rules.  Using the attach part of `test.sh` in this directory, replacing
`--attach` with `--update` yields the update command.

```
sudo ${BUILD_PATH}/xdp_fw/xdp_fw --debug --update --rules my-cool.rule --interface ${INTERFACE} --program ${BUILD_PATH}/xdp_fw/xdp_fw_kern.o
```

### Inplace Updates

There was initially a sceme to allow for inplace rule updates.  This was
removed since the main intention of the xdp_fw is ddos defence, not
general firewalling.  We also work around kernel/userland mismatches.

The way the system worked was to store a ruleset
revision between 1 and 1023 in a map.  Before updating the rules, this
revision would be set to zero.  After the rules were updated, the revision
would be set to 1 + the previous revision modulo 1024.  In the kernel,
we would fetch the revision before processing a packet.  Before dropping a
packet, we would do another revision lookup and make sure the revision at 
the start and end were the same.  If not, the packet got a pass.

## Performance

Using `./test.sh -bPt` you can collect some statistics on simulated runs through the
firewall into `test-log.csv`.  The resulting statitics are easily worked with using R.
For example, to see the difference in time between a dropped packet and passed, you can
do:

```
stats = read.csv("test-log.csv")
mean(stats[stats$ret == "XDP_DROP", "min"])
mean(stats[stats$ret == "XDP_PASS", "min"])
mean(stats[stats$ret == "XDP_DROP", "min"]) - mean(stats[stats$ret == "XDP_PASS", "min"])
```

```
> stats = read.csv("test-log.csv")
> mean(stats[stats$ret == "XDP_DROP", "min"])
[1] 70.05063
> mean(stats[stats$ret == "XDP_PASS", "min"])
[1] 48.91339
> mean(stats[stats$ret == "XDP_DROP", "min"]) - mean(stats[stats$ret == "XDP_PASS", "min"])
```

## Rule metadata

For tracking where various rules came from there is the `name` option:

```
ip from {192.168.56.20/32} to any icmp name "drop ping from client"
```

The `name` is available in the stats output:

```
vagrant@server:/vagrant/xdp_fw$ sudo ${BUILD_PATH}/xdp_fw/xdp_fw --interface ${INTERFACE}  --stats
{
  "enp0s8":[
    {
      "rule_number":0,
      "hits":0,
      "name":"drop google dns",
      "rule":"packet length any ip from { 8.8.8.8\/16 } to { any } ttl any icmp type any name \"drop google dns\""
    },
    {
      "rule_number":1,
      "hits":1,
      "name":"drop ping from client",
      "rule":"packet length any ip from { 192.168.56.20\/32 } to { any } ttl any icmp type any name \"drop ping from client\""
    }
  ]
}
```

# Testing

There are two test modes.  One is using the Vagrant environment to do dev/test cycles and another
unit test mode.


## Vagrant build/test

There is a `Vagrantfile` in the root of this repository and notes about it in the main README.md.

The `test.sh` file in `xdp_fw` contains a bunch of shortcuts for building and loading the firewall
on the `server` vagrant machine.

```
vagrant@server:/vagrant/xdp_fw$ ./test.sh -h
test.sh
 -a attach and use test/host-test.rules
 -d detach
 -t test
 -s stats
 -r <rules file> Use rules file for test
 -p <pacp file> Use pcap file for test
 -P build without debug
 -d dump assembly
 -l run with lldb
 -b build
 -m monitor
```

To load the firewall on the server, use `./test.sh -a` to attach it.
By default, the rules in `tests/host-test.rules` are loaded.

```
vagrant@server:/vagrant/xdp_fw$ cat tests/host-test.rules 
ip from {8.8.8.8/16} to any icmp
ip from {192.168.56.20/32} to any icmp
```

The debug build has extensive logging via `bpf_debug` which is a wrapper for printk.  Use
`./test.sh -m` to monitor.

```
<idle>-0       [001] d.s.1  2033.156181: bpf_trace_printk: -------- START PACKET --------
<idle>-0       [001] dNs.1  2033.156253: bpf_trace_printk: fw_ruleset_array_q: value 0x62 matches 0x3
<idle>-0       [001] dNs.1  2033.156254: bpf_trace_printk: fw_ruleset_array_q: value 0x1 matches 0x3
<idle>-0       [001] dNs.1  2033.156255: bpf_trace_printk: fw_ruleset_array_q: value 0x40 matches 0x3
<idle>-0       [001] dNs.1  2033.156257: bpf_trace_printk: fw_ruleset_ip_addr_q: addr: c0a8380a matches 0x3
<idle>-0       [001] dNs.1  2033.156258: bpf_trace_printk: fw_ruleset_ip_addr_q: addr: c0a83814 matches 0x2
<idle>-0       [001] dNs.1  2033.156259: bpf_trace_printk: fw_ruleset_array_q: value 0x8 matches 0x3
<idle>-0       [001] dNs.1  2033.156260: bpf_trace_printk: xdp_fw_entry: All matches 0x2 Matching Rule: 1
<idle>-0       [001] dNs.1  2033.156261: bpf_trace_printk: xdp_fw_entry: returning XDP_DROP
<idle>-0       [001] dNs.1  2033.156262: bpf_trace_printk: update_stat_counters: slot 5 act 1 to 1
```

## Unit Test

The `tests/` subdirectory contains a pcap file with a collection
of expample packets and a bunch of rules files.  These rules files
contain both rules and expected outcomes based on packet hash.

```
ip from any to any ttl 119 tcp
ip6 from any to any ttl 64 icmp6

# Protocol mismatch for 4629d8d8b2c9ba0d082b503f96636cc7798a717e
ip from {104.229.56.29/32} to any ttl 56 udp

#Len 60 IPv4 Src 99.179.48.253 -> Dst 152.195.8.8 ttl 119 proto tcp sport 50633 -> dport 80 window 4160 flags ( ack )
test sha1 5ee7710e4f59c537e76c9d243658931828ce296d xdp_action XDP_DROP

#Len 66 IPv4 Src 104.229.56.29 -> Dst 152.195.8.23 ttl 56 proto tcp sport 39546 -> dport 443 window 31889 flags ( ack )
test sha1 4629d8d8b2c9ba0d082b503f96636cc7798a717e xdp_action XDP_PASS
```

Tests can be run using the `./test.sh` script with the `-t` option.

```
vagrant@server:/vagrant/xdp_fw$ ./test.sh -t
libecbpf: INFO: Mounting BPF filesystem
DUMPING RULES


packet length any ip from { any } to { any } ttl any tcp window any sport { 1-65535 } flags 00 mask 00 name \"no name\"
test sha1 0e3c40feb7eee8af30933a08dc1de9476f129005 xdp_action XDP_PASS
test sha1 139f94fc8695bf89a4811ee707c73720749bb6fa xdp_action XDP_DROP
test sha1 1701a3c99fccebfcf4b4a53e18cbce9808947623 xdp_action XDP_DROP
test sha1 1b315f8fa2592a07f4dc715d4d4a7a7e6f983e0a xdp_action XDP_PASS
test sha1 1fb42177fa275bff6c456385abd198b59980bf7e xdp_action XDP_DROP
test sha1 2b255e1a865cf85dee1d9aef7898d4f9717a2fd4 xdp_action XDP_PASS
test sha1 2c306899553189c8c2520b19edf45f4d037b44a4 xdp_action XDP_PASS
test sha1 35872635ca7d8fcde150de21684df8269473cd36 xdp_action XDP_PASS
test sha1 4629d8d8b2c9ba0d082b503f96636cc7798a717e xdp_action XDP_PASS
test sha1 47671b6f534c48f12cece160496f376bc6a64e4a xdp_action XDP_PASS
test sha1 5d1cb87352d541bebc0dbf19d4c7d5ff565c3deb xdp_action XDP_PASS
test sha1 5ee7710e4f59c537e76c9d243658931828ce296d xdp_action XDP_PASS
test sha1 7d95c045646a089fae7969a974d96d921787bd55 xdp_action XDP_PASS
test sha1 899e948ba034685eec9f504559cf19a399306fa4 xdp_action XDP_PASS
test sha1 8a1f4ba95963c8492cf68c3396968228d48a6b65 xdp_action XDP_DROP
test sha1 9122f181f68fe207999f5c28d4a10ddee6d4ee56 xdp_action XDP_PASS
test sha1 a4e2b57da7904c7a5bab70eb9c35a5da14403aea xdp_action XDP_PASS
test sha1 a4298a0983ca63099cf2dd4c35147390d088fdb8 xdp_action XDP_PASS
test sha1 c53642ce08b6704c547c58db9c6107963c9aaaf4 xdp_action XDP_PASS
test sha1 ce9ae000e1a067fe58ffba1bb0242fb2643c1a2e xdp_action XDP_PASS
test sha1 d3990ec4cdcdd342de7bb5e5a3842cae8cb12ea1 xdp_action XDP_PASS
test sha1 e1b0527f80aa8fe1aa4bd3de7989b02c37847a89 xdp_action XDP_DROP
test sha1 fdf43be460097ab7dfff28ed3754c04c9494819d xdp_action XDP_DROP
END DUMPING RULES


Map update: 0/0
Map update: 0/0
Len 60 IPv4 Src 99.179.48.253 -> Dst 152.195.8.8 ttl 119 proto tcp sport 50633 -> dport 80 window 4160 flags ( ack )
 test sha1 5ee7710e4f59c537e76c9d243658931828ce296d xdp_action XDP_PASS
 pkt ts: 1621475998.27 caplen: 60 average: 4248.632000 ns min: 3517 max: 35011
 test pass

Len 66 IPv4 Src 104.229.56.29 -> Dst 152.195.8.23 ttl 56 proto tcp sport 39546 -> dport 443 window 31889 flags ( ack )
 test sha1 4629d8d8b2c9ba0d082b503f96636cc7798a717e xdp_action XDP_PASS
 pkt ts: 1621475998.77 caplen: 66 average: 3988.228000 ns min: 3487 max: 10086
 test pass
```

# IPTables Rules generation

## Current Rule generation

* Packet Length
* Source IP
* Destination IP
* Destination Port
* Protocol
* IP TTL/IPv6 Hop Limit
* TCP Flags/Flag mask
* TCP Window

