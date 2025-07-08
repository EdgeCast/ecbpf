#!/bin/bash

set -u

function usage() {
	echo "test.sh"
	echo " -a attach"
	echo " -d detach"
	echo " -b build"
	echo " -c clean"
	echo " -m monitor"
	echo " -D drop"
	echo " -f filter"
	echo " -s status"
	echo " -s statsd logging"
	echo " -j json status"
	echo " -v valgrind"
	exit "$1"
}

lldb=""
valgrind=""

while getopts ":admbcDsShjvf" opt; do
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
		f)
			filter=1
			;;
		D )
			drop=1
			;;
		s )
			status=1
			;;
		S )
			statsd=1
			;;
		j )
			json=1
			;;
		v )
			valgrind="valgrind --leak-check=full --show-leak-kinds=all"
			;;
		h )
			usage 0
			;;
		*)
			usage 1
			;;
	  esac
done

if [[ -v build ]]; then
	rm ${BUILD_PATH}/xdp_filter/xdp_filter_kern.o || true
	rm -r ${BUILD_PATH}/*  || true
	pushd ${BUILD_PATH} || exit 1
	cmake .. || exit 1
	make VERBOSE=1 || exit 1
	popd || exit 1
fi

if [[ -v attach ]] ; then
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --detach --interface ${INTERFACE}
	echo "Root detach done"
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --attach --interface ${INTERFACE} --filename ${BUILD_PATH}/xdp_root/xdp_root_kern.o
	echo "Root attach done"
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --attach --interface ${INTERFACE} --program ${BUILD_PATH}/xdp_filter/xdp_filter_kern.o
	exit 0
fi

if [[ -v detach ]] ; then
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --detach --interface ${INTERFACE}
	exit 0
fi

if [[ -v monitor ]]; then
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --trace
fi

if [[ -v drop ]]; then
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --drop --ips '192.168.56.0/24,192.168.66.0/24' -t '56 subnet,66 subnet'
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter  --interface ${INTERFACE} --drop --ips '2606:2800:3::/64','2606:2800:3::/48' -t  '/64 v6,/48 v6'
fi

if [[ -v filter ]]; then
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --frags-drop --ptb-max-pps 20
fi

if [[ -v status ]]; then
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --status
fi

if [[ -v json ]]; then
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --status --json
fi

if [[ -v statsd ]]; then
	sudo ${valgrind} ${BUILD_PATH}/xdp_filter/xdp_filter --interface ${INTERFACE} --attach --statsd \
		--program ${BUILD_PATH}/xdp_filter/xdp_filter_kern.o --statsd-detach-on-exit \
		#--statsd-host asdf --statsd-port 12345
fi
