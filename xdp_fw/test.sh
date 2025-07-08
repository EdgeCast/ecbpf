#!/bin/bash

set -u

declare -A testfiles

# Default tests in tests/
testfiles["ip-length.rules"]="all.pcapng"
testfiles["ip46-ttl.rules"]="all.pcapng"
testfiles["ip46-specific.rules"]="all.pcapng"
testfiles["ip6-length.rules"]="all.pcapng"
testfiles["ip-addr.rules"]="all.pcapng"
testfiles["ip6-addr.rules"]="all.pcapng"
testfiles["ip-any-tcp.rules"]="all.pcapng"
testfiles["ip-any-tcp-syn.rules"]="all.pcapng"
testfiles["ip-any-tcp-syn-psh.rules"]="all.pcapng"
testfiles["ip46-any-tcp-ack.rules"]="all.pcapng"
testfiles["ip46-any-tcp-syn-psh.rules"]="all.pcapng"
testfiles["ip46-any-tcp-window.rules"]="all.pcapng"
testfiles["ip46-any-tcp-port.rules"]="all.pcapng"
testfiles["ip46-any-udp-port.rules"]="all.pcapng"
testfiles["ip6-any-tcp.rules"]="all.pcapng"
testfiles["ip6-any-tcp-syn.rules"]="all.pcapng"
testfiles["ip-any-icmp-code.rules"]="all.pcapng"
testfiles["ip6-any-icmp6-code.rules"]="all.pcapng"
testfiles["ip-any-icmp-any.rules"]="all.pcapng"
testfiles["ip6-any-icmp6-any.rules"]="all.pcapng"

function usage() {
	echo "test.sh"
	echo " -a attach and use test/host-test.rules"
	echo " -d detach"
	echo " -t test"
	echo " -s stats"
	echo " -r <rules file> Use rules file for test"
	echo " -p <pacp file> Use pcap file for test"
	echo " -P build without debug"
	echo " -D dump assembly"
	echo " -l run with lldb"
	echo " -b build"
	echo " -m monitor"
	echo " -v validate"
	exit "$1"
}

lldb=""

while getopts ":htdDbmr:p:Pladsv" opt; do
	case ${opt} in
		a )
			attach=1
			;;
		d )
			detach=1
			;;
		m )
			monitor=1
			;;
		b )
			build=1
			;;
		c )
			clean=1
			;;
		t )
			test=1
			;;
		D )
			dump=1
			;;
		l )
			lldb="lldb-9 -- "
			;;
		p)
			pcap="${OPTARG}"
			if [[ ! -f "${pcap}" ]]; then
				echo "PCAP file ${pcap} does not exist"
				exit 1
			fi
			;;
		P )
			export FW_PERF_TEST=1
			;;
		r)
			rules="${OPTARG}"
			if [[ ! -f "${rules}" ]]; then
				echo "Ruels file ${rules} does not exist"
				exit 1
			fi
			;;
		s)
			stats=1
			;;
		v)
			validate=1
			;;
		h )
			usage 0
			;;
		*)
			usage 1
			;;
	  esac
done

if [[ -v stats ]]; then
	sudo ${lldb} ${BUILD_PATH}/xdp_fw/xdp_fw --stats --interface ${INTERFACE}
	exit 0
fi

if [[ -v validate ]]; then
	sudo ${lldb} ${BUILD_PATH}/xdp_fw/xdp_fw --debug --validate --rules "${rules:-tests/host-test.rules}"
fi

if [[ -v attach ]] ; then
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --detach --interface ${INTERFACE}
	echo "Root array detach done to level set all XDP state"
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --attach --interface ${INTERFACE} --filename ${BUILD_PATH}/xdp_root/xdp_root_kern.o
	echo "Root array attach done"
	sudo ${lldb} ${BUILD_PATH}/xdp_fw/xdp_fw --debug --attach --rules "${rules:-tests/host-test.rules}" --interface ${INTERFACE} --program ${BUILD_PATH}/xdp_fw/xdp_fw_kern.o
	echo "XDP Firewall attach done"
	exit 0
fi

if [[ -v detach ]] ; then
	sudo ${BUILD_PATH}/xdp_fw/xdp_fw --debug --detach --interface ${INTERFACE}
	echo "XDP Firewall subprogram detached from root array.  Root array left loaded."
	exit 0
fi

if [[ -v monitor ]]; then
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --trace
fi

if [[ -v dump ]]; then
	llvm-objdump -S ${BUILD_PATH}/xdp_fw/xdp_fw_kern.o
	exit 0
fi

if [[ -v build ]]; then
	rm ${BUILD_PATH}/xdp_fw/xdp_fw_kern.o || true
	rm -r ${BUILD_PATH}/*  || true
	pushd ${BUILD_PATH} || exit 1
	cmake .. || exit 1
	make VERBOSE=1 || exit 1
	popd || exit 1
fi

if [[ -v test ]]; then
	if [[ -v rules && -v pcap ]] ; then
		sudo ${lldb} ${BUILD_PATH}/xdp_fw/xdp_fw --test "${pcap}" --rules "${rules}" \
			--program ${BUILD_PATH}/xdp_fw/xdp_fw_kern.o
	else
		rm test-log.csv
		for key in "${!testfiles[@]}" ; do
			sudo ${lldb} ${BUILD_PATH}/xdp_fw/xdp_fw --test "tests/${testfiles[${key}]}" --rules "tests/${key}" \
				--program ${BUILD_PATH}/xdp_fw/xdp_fw_kern.o \
				--test-log test-log.csv
			if [[ $? -ne 0 ]]; then
				echo tests/${key} failed 
				exit 1
			fi
		done

	fi
	exit 0
fi
