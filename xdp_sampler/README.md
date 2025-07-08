# XDP Sampler

This XDP program samples incoming packets for use of DDoS, stats and debugging.

# Architecture

The `xdp_sampler_kern.c` randomly samples packets and puts them into a
perf event ring.  `xdp_sampler.c` handles loading the XDP program.  It
also reads the perf event ring for sampled packets.  It places the sample
into a protobuf and adds some metadata suchs as host and NIC.  This protobuf
is published out over zeromq.  `xdp_sampler_to_pcap.c` will listen to the zeromq
bus and output packet samples in pcap format.  

# Multinic

For G8 hardware, we may have to sample two interfaces.  Since the
program that publishes the packets on zmq also reads the buffer,
adding in a topic doesn't seem useful.  G8 hardware can't currently
run XDP programs because of ixgbe driver limitations.  We will
have to extend the sampler to support multiple nics or run two
instances on different ports.

# Testing

There is a `test.sh` script that automates routine testing.

```
vagrant@server:/vagrant/xdp_sampler$ ./test.sh
test.sh
 -a attach
 -t teardown
 -m monitor
 -b build
 -p install packet connector dev deb
```

Attach and run the sampler process.

```
vagrant@server:/vagrant/xdp_sampler$ ./test.sh -a
libecbpf: INFO: Can't stat map path /sys/fs/bpf/enp0s8: No such file or directory
Failed to detach root program on interface enp0s8libbpf: loading /vagrant/build/xdp_root/xdp_root_kern.o
libbpf: elf: section(3) xdp_root, size 376, link 0, flags 6, type=1
libbpf: sec 'xdp_root': found program 'xdp_root_prog' at insn offset 0 (0 bytes), code size 47 insns (376 bytes)
libbpf: elf: section(4) .relxdp_root, size 144, link 21, flags 0, type=9
libbpf: elf: section(5) .maps, size 96, link 0, flags 3, type=1
libbpf: elf: section(6) license, size 4, link 0, flags 3, type=1
libbpf: license of /vagrant/build/xdp_root/xdp_root_kern.o is APL 
libbpf: elf: section(12) .BTF, size 1214, link 0, flags 0, type=1
libbpf: elf: section(14) .BTF.ext, size 112, link 0, flags 0, type=1
libbpf: elf: section(21) .symtab, size 312, link 1, flags 0, type=2
```

You can use `test.sh -m` to monitor sampled packets.  Samples can be caused by
flood pinging the server from the client virtual machine.

```
vagrant@server:/vagrant/xdp_sampler$ ./test.sh -m
reading from file -, link-type EN10MB (Ethernet)
03:16:59.016652 08:00:27:b9:df:22 > 08:00:27:58:6d:1d, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 46735, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.56.20 > 192.168.56.10: ICMP echo request, id 1, seq 542, length 64
        0x0000:  4500 0054 b68f 4000 4001 92aa c0a8 3814  E..T..@.@.....8.
        0x0010:  c0a8 380a 0800 f7a8 0001 021e aa81 6d64  ..8...........md
        0x0020:  0000 0000 257f 0200 0000 0000 1011 1213  ....%...........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567
03:17:01.957167 08:00:27:b9:df:22 > 08:00:27:58:6d:1d, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 52398, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.56.20 > 192.168.56.10: ICMP echo request, id 1, seq 6205, length 64
        0x0000:  4500 0054 ccae 4000 4001 7c8b c0a8 3814  E..T..@.@.|...8.
        0x0010:  c0a8 380a 0800 937e 0001 183d ad81 6d64  ..8....~...=..md
        0x0020:  0000 0000 718a 0100 0000 0000 1011 1213  ....q...........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567
```
