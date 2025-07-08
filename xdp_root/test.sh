#!/bin/bash


while getopts "adn" opt; do
	case ${opt} in
		a )
			attach=1
			;;
		d )
			detach=1
			;;
		n )
			nop=1
			;;
	esac
done


if [[ -v attach ]] ; then
	set -x
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader \
		--debug \
		--generic \
	       	--attach \
	       	--interface ${INTERFACE} \
	       	--filename ${BUILD_PATH}/xdp_root/xdp_root_kern.o
	set +x
	exit 0
fi

if [[ -v detach ]] ; then
	if [[ -v nop ]] ; then
		opt=" --nop --filename ${BUILD_PATH}/xdp_root/xdp_root_nop_kern.o "
	else
		opt=""
	fi

	set -x
	sudo ${BUILD_PATH}/xdp_root/xdp_root_loader \
		--debug \
		--generic \
		--detach \
		${opt} \
		--interface ${INTERFACE}
	set +x
	exit 0
fi
