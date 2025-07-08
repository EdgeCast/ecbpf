#!/bin/bash

#
# This script uses network namespaces to test the XDP sampler
# with high load on two nics.
#

BUILD_PATH=../build

SERVER0_ADDR=172.12.0.100
SERVER1_ADDR=172.12.1.101
CLIENT0_ADDR=172.12.0.1
CLIENT1_ADDR=172.12.1.2

setup() {
	for ns in server0 server1 client ; do
		ip netns add ${ns}
	done

	# Create interfaces
	ip link add server0 netns server0 type veth peer name client0 netns client
	ip link add server1 netns server1 type veth peer name client1 netns client

	# Configure interfaces
	ip netns exec server0 ip addr add ${SERVER0_ADDR}/24 dev server0
	ip netns exec server1 ip addr add ${SERVER1_ADDR}/24 dev server1
	ip netns exec client ip addr add ${CLIENT0_ADDR}/24 dev client0
	ip netns exec client ip addr add ${CLIENT1_ADDR}/24 dev client1

	# Bring up interfaces
	for ns in server0 server1 client ; do
		ip netns exec $ns ip link set lo up
	done

	ip netns exec server0 ip link set server0 up
	ip netns exec server1 ip link set server1 up

	for i in client0 client1 ; do
		ip netns exec client ip link set $i up
	done

	# Originally I attempted to use two namespaces, but traffic even with
	# binding, all traffic would go over one interface, so there are two server
	# namespaces and two iperf servers.
	ip netns exec server0 iperf -s &
	IPERF0_PID=$!
	ip netns exec server1 iperf -s &
	IPERF1_PID=$!
	sleep 1 # In the jungle, the mighty jungle, the rubber chicken sleeps tonight
}

iperf_test() {
	ip netns exec client iperf -c ${SERVER0_ADDR} -B ${CLIENT0_ADDR} --time ${RUNTIME} -d &
	one=$!
	ip netns exec client iperf -c ${SERVER1_ADDR} -B ${CLIENT1_ADDR} --time ${RUNTIME} -d &
	two=$!

	wait $one
	wait $two
}

xdp() {
	# For whatever reason, bpf sysfs mounts do not continue to exist
	# between ip netns exec sessions...  So we put everything into one
	# subshell.  Mind the escapes.
	ip netns exec client bash <<- EOF &
	${BUILD_PATH}/xdp_root/xdp_root_loader --generic --attach --interface client0,client1 --filename ${BUILD_PATH}/xdp_root/xdp_root_kern.o

	${VALGRIND} ${BUILD_PATH}/xdp_sampler/xdp_sampler \
			--debug --program ${BUILD_PATH}/xdp_sampler/xdp_sampler_kern.o --port 12354  \
			--interface client0-client1 --statsd &
	samp_pid=\$!
	function cleanup() {
		echo "Cleaning up subshell by killing sampler \$samp_pid"
		kill \$samp_pid
		wait \$samp_pid
		echo "Subshell sampler dead"
	}
	trap cleanup EXIT SIGINT
	echo Subshell in client namespace WAITING ON SAMPLER: \$samp_pid
	wait \$samp_pid
	EOF
	SAMPLER_PID=$!
}

teardown() {
	if [[ -v IPERF0_PID ]];  then
		echo "Killing iperf in server0"
		kill "$IPERF0_PID"
		wait "$IPERF0_PID"
	fi

	if [[ -v IPERF1_PID ]];  then
		echo "Killing iperf in server1"
		kill "$IPERF1_PID"
		wait "$IPERF1_PID"
	fi

	if [[ -v SAMPLER_PID ]];  then
		echo "Killing sampler"
		kill "$SAMPLER_PID"
		wait "$SAMPLER_PID"
	fi

	for ns in server0 server1 client; do
		ip netns del ${ns}
	done
}

usage() {
	echo "-v Enable valgrind"
	echo "-r <num> Runtime in seconds"
}

if [[ $UID != 0 ]]; then
	echo "Must run as root!"
	exit
fi

RUNTIME=10
VALGRIND=

while getopts r:vh flag
do
	case "${flag}" in
		r)
			RUNTIME=${OPTARG}
			;;
		v)
			VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
			;;
		h)
			usage
			exit
			;;
	esac
done

trap teardown EXIT SIGINT
setup
xdp
iperf_test
