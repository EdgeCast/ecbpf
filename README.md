# ecbpf

This package contains libbpf, the headers for libbpf, and the ack fast path programs.

## Operations

### Systemd

The root array and subprograms are all controlled by systemd unit files.  These
unit files call `ecbpf_service_handler.py` which handles figuring out which
interfaces to attach to and performs some sanity checking prior to attaching.

All the systemd unit files start with `ecbpf-`:

```
# systemctl status ecbpf-
ecbpf-bypass.service        ecbpf-filter.service        ecbpf-sampler.service       
ecbpf-bypass-stats.service  ecbpf-root.service          
```

### Root array status

Calling `xdp_root_loader --status` will show what subprograms are loaded in each root 
array slot.  It is not necessary to supply an interface for this.  JSON output is supported
by calling `xdp_root_loader --status --json`.

```
# xdp_root_loader --status
Inferface eth0 status:
SLOT | ID    | NAME                     | LOAD TIME                            | XDP_ABORTED      | XDP_DROP         | XDP_PASS         | XDP_TX           | XDP_REDIRECT     | XDP_INVALID_ACTION
   0 |     - | -                        | -                                    |                0 |                0 |                0 |                0 |                0 |                0
   1 |    16 | xdp_sampler_pro          | Wed, 03 May 2023 20:18:12 +0000      |                0 |                0 |              310 |                0 |                0 |                0
   2 |  2257 | xdp_filter_prog          | Fri, 29 Sep 2023 23:02:07 +0000      |                0 |           330948 |              450 |           330790 |                0 |                0
   3 |     - | -                        | -                                    |                0 |                0 |                0 |                0 |                0 |                0
   4 |     - | -                        | -                                    |                0 |                0 |                0 |                0 |                0 |                0
   5 |     - | -                        | -                                    |                0 |                0 |                0 |                0 |                0 |                0
   6 |     - | -                        | -                                    |                0 |                0 |                0 |                0 |                0 |                0
   7 |  1383 | xdp_bypass_ipvs          | Fri, 21 Jul 2023 20:37:56 +0000      |                0 |                0 |        931591053 |       7382076749 |                0 |                0

Inferface eth1 status:
Root array not attached to interface eth1.

```

### XDP Filter status

The status of the XDP filter can be checked by calling
`xdp_filter --status --interface <comma separated list of interfaces>`.  JSON
output is supported by adding a `--json`.

```
# xdp_filter --status --interface eth0 
=================== Status for interface 'eth0' ===================
Current Configuration:

frags_drop? true
ptb_send? true
ptb_max_pps: 20

Drop Maps for interface 'eth0':


Stats for interface 'eth0':

eth_frame_err: 0
ip_header_err: 0
ip6_header_err: 0
ip_drop_count: 0
ip6_drop_count: 0
ip_frag_drop_count: 0
ptb_sent_count: 0
ptb_err_count: 0
ptb_mem_err_count: 0
```

## Prerequisites

In order to build, you need [Docker](https://www.docker.com/) installed and internet access.

## Libbpf

Updating to a newer version of libbpf can be done via a git subtree pull.

```
git subtree pull --squash -m "Pull in libbpf v0.0.9" --prefix=ext/libbpf https://github.com/libbpf/libbpf.git v0.0.9
```

## Building a package

### Docker

The `Makefile.docker` contains a `package` and `shell` target, which is the default target
Package is deposited in dist/.

For testing, use of the included Vagrant environment is encouraged.  Locally building a package
is handy for testing in prod or prod-like machines.

To build locally, run:

```
make -f Makefile.docker package
```

To get a shell in the docker, run:

```
make -f Makefile.docker shell
```

### Vagrant

You can also build a package in the Vagrant environment, but it will be of limited use
since `scripts/ecpbf_service_handler.py` requires a EC style networking setup (the script
exists mainly to determine ingress/egress interfaces on the Edge using bond0, lldp, etc).

```
vagrant@server:/vagrant/build$ make package
...
CPack: - Run preinstall target for: ecbpf
CPack: - Install project: ecbpf []
CPack: Create package
CPack: - package: /vagrant/build/ecbpf_0.0.1~focal_amd64.deb generated.
vagrant@server:/vagrant/build$ sudo dpkg -i 
```

### Vagrant Box Update Bug

There is a bug where `vagrant box update` will not see the latest versions.  It is documented
[here](https://github.com/hashicorp/vagrant/issues/13345).  You can work around this by going
outside of the `ecbpf` repo and running:

```
vagrant box update --box ubuntu/jammy64
Checking for updates to 'ubuntu/jammy64'
Latest installed version: 20230929.0.0
Version constraints: > 20230929.0.0
Provider: virtualbox
Updating 'ubuntu/jammy64' with provider 'virtualbox' from version
'20230929.0.0' to '20240701.0.0'...
Loading metadata for box 'https://vagrantcloud.com/ubuntu/jammy64'
Adding box 'ubuntu/jammy64' (v20240701.0.0) for provider: virtualbox
Downloading: https://vagrantcloud.com/ubuntu/boxes/jammy64/versions/20240701.0.0/providers/virtualbox/unknown/vagrant.box
Download redirected to host: cloud-images.ubuntu.com
Successfully added box 'ubuntu/jammy64' (v20240701.0.0) for 'virtualbox'!
```

## Debugging

The preprocessor variable `NDEBUG` is set when building in travis.  Right now this
disables `bpf_printf` as defined in `libecbpf/libecbpf_kern.h`

## Manual building

There is a `build/` subdirectory.  The `cmake` build process is fairly simple:

```
cd build/
cmake ..
make # VERBOSE=1 for debugging
make package # Creates a debian package
```

### Build/Test Vagrant environment

There is a `Vagrantfile` for testing in the root of the project.  Most components
(xdp_sampler, xdp_fw, and xdp_filter) have a `test.sh` shell script to help with
attaching and running inside of this environment.

The Vagrant environment requires two plugins at the moment.

```
# vagrant plugin install vagrant-vbguest
# vagrant plugin install vagrant-reload
```

The environment currently consists of two machines, `server` and `client`.

```
# vagrant up
Bringing machine 'server' up with 'virtualbox' provider...
Bringing machine 'client' up with 'virtualbox' provider...
```

The repo is mounted on `server` under `/vagrant`.

```
$ vagrant ssh server
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-72-generic x86_64)

Last login: Tue May 16 22:31:02 2023 from 10.0.2.2
vagrant@server:~$ cd /vagrant/
vagrant@server:/vagrant$ ls
ARCHITECTURE.md  Makefile.docker  Vagrantfile  build.sh     cap.pcap  docs                               ext       scripts  ubuntu-bionic-18.04-cloudimg-console.log  xdp_fw      xdp_root
CMakeLists.txt   README.md        build        bypass_ipvs  dist      ec-xdpcap_0.0.0-0+focal_amd64.deb  libecbpf  tests    xdp_filter                                xdp_printk  xdp_sampler
vagrant@server:/vagrant$
```

Some environmental variables are set by `/etc/profile.d/xdp_test_env.sh`.

```
vagrant@server:~$ cat /etc/profile.d/xdp_test_env.sh
export INTERFACE=enp0s8
BUILD_PATH=/vagrant/build
```

An initial build should be done during `vagrant up`.  Installation of dependencies
and the initial build are done by calling the `build.sh` script.  Component test
scripts also handle rebuilding, so normally you will call `./test.sh -b` in the
component you are working on.

```
vagrant@server:/vagrant$ ./build.sh -b
-- The C compiler identification is Clang 12.0.0
-- The CXX compiler identification is GNU 9.4.0
-- Check for working C compiler: /usr/bin/clang
-- Check for working C compiler: /usr/bin/clang -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found ZLIB: /usr/lib/x86_64-linux-gnu/libz.so (found version "1.2.11") 
Building xdp_root_kern.c to xdp_root_kern.o
Building xdp_printk_kern.c to xdp_printk_kern.o
....
```


## Notes

### Compile once, run everywhere

We don't need to worry about this at this time.  The main kernel structure we would need to
worry about is already handled via `struct __sk_buff`.  A good overview of `struct __sk_buff` can
be found [here](https://medium.com/@c0ngwang/understanding-struct-sk-buff-730cf847a722).  In general
CO-RE seems to be more of an issue with performance monitoring.  If we need to support it in the
future, a good overview of CO-RE can be found [here](https://nakryiko.com/posts/bpf-portability-and-co-re/).

### BPF to BPF Calls

For the `xdp_fw` in particular, it would be nice to use BPF to BPF
calls.  We can't do this until Kernel 5.13 because BPF to BPF calls
were incompatible with BPF tail calls.  The patch
[e411901c0b775a3ae7f3e2505f8d2d90ac696178](https://github.com/torvalds/linux/commit/e411901c0b775a3ae7f3e2505f8d2d90ac696178)
enabled the combination of the two.

### Moving away from object files

The [libbpf skeleton files](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-object-skeleton-file) provide
a way to move away from working with object files.  The bpf programs are compiled down into byte code and turned
into header files.  This would simplify things quite a bit with managing various object files.  The skeleton files
also provide support for manipulating global variables inside a eBPF program.

### Global variables

As a way to share state between calls, libbpf supports global variables.  The libbpf skeleton files mentioned
above [provide a way](https://libbpf.readthedocs.io/en/latest/libbpf_overview.html#other-advantages-of-using-skeleton-file)
to seed these global variables as well as fetch and update them later.

These globals come with certain performance improvements.  See [this kernel commit message](https://lore.kernel.org/bpf/20190228231829.11993-7-daniel@iogearbox.net/t/)
for details.

This may be a useful way to bake in internal ip addresses or vip blocks with high performance.  We can also save on repeatedly
processing what sort of packet we are dealing with between calls (IPv4 vs v6, etc).  I think this is what 
cloudflare does with some of their stuff.  It may also make handling configuration options faster, but I would need to 
double check this.  A [stack overflow answer](https://stackoverflow.com/questions/70475993/how-to-let-user-space-to-populate-an-ebpf-global-data-at-load-time) 
provides some direction on doing this with libbpf.  Two main things from the article worth rementioning are:

 * Global variables become special maps--see [bpf_object__init_internal_map](./ext/libbpf/src/libbpf.c#L1528).
 * Kernel tests may be useful for interacting with internal maps-- see [linux/tools/testing/selftests/bpf/prog_tests
/global_data.c](https://github.com/torvalds/linux/blob/8efd0d9c316af470377894a6a0f9ff63ce18c177/tools/testing/selftests/bpf/prog_tests/global_data.c#L103)



### Tail Call Alternatives

The keyword to look for here is "xdp dispatcher".  Instead of using tail calls, stub functions are used.  It is a part of
[libxdp](https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/README.org).

See the dispatcher docs at [https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/protocol.org](https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/protocol.org).

We may want to combine global variables and some concepts from the dispatcher to pass metadata between subprograms.
With our current tail call method, each subprogram starts fresh and has to reprocess the same things about a packet
each time.  If would could provide a struct with the necessary metadata it might result in a speed increase between
various subprograms/functions.
