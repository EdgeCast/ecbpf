#!/bin/bash

set -u

function usage() {
	echo "test.sh"
	echo " -a attach"
	echo " -t teardown"
	echo " -m monitor"
	echo " -b build"
	echo " -p install packet connector dev deb"
	exit 0
}


while getopts ":hatmbp" opt; do
	case ${opt} in
	a )
		attach=1
		;;
	t )
		teardown=1
		;;
	m )
		monitor=1
		;;
	b )
		build=1
		;;
	p )
		packet_connector=1
		;;
        h )
		usage
		;;
        * )
		usage
		;;
	esac
done

if [[ -v build ]]; then
	rm ${BUILD_PATH}/xdp_sampler/xdp_sampler_kern.o || true
	cd ${BUILD_PATH}
	make
	exit 0
fi

if [[ -v attach ]]; then
	sudo hostname server.pop
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --detach --interface ${INTERFACE}
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --attach --interface ${INTERFACE} --filename ${BUILD_PATH}/xdp_root/xdp_root_kern.o
	sudo ${BUILD_PATH}/xdp_sampler/xdp_sampler --debug --port 12354 --interface ${INTERFACE} --statsd
	exit 0
fi

if [[ -v teardown ]]; then
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader --debug --generic --detach --interface ${INTERFACE}
	exit 0
fi

if [[ -v monitor ]]; then
	sudo ${BUILD_PATH}/xdp_sampler/xdp_sampler_to_pcap --debug --port 12354 --output - | tcpdump -r - -v -n -e -X
	exit 0
fi

if [[ -v packet_connector ]] ; then
	sudo dpkg -i /vagrant/ec-packetconnector_0.0.0-0+bionic_amd64.deb

	sudo sh -c "cat > /opt/PacketConnector/etc/PacketConnector.conf" <<- EOF
	{
		"zmqPort": 12354,
		"sdiLogHost": "localhost",
		"sdiLogPort": 8844
	}
EOF
	exit 0
fi


usage
