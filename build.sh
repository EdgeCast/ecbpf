#!/bin/bash

# Build the ecbpf package.  This script is to be run from inside a container.
set -eu
set -o pipefail
export DEBIAN_FRONTEND=noninteractive # tzdata can muck things up

if [[ -v CI ]]; then # Being run inside gitlab
	set -x
fi

LLVM_POSTFIX=-15
CLONE_DIR=$(cd $(dirname "$0") && pwd)

function install_packages() {
	apt-get update
	apt-get --yes install build-essential libelf-dev libssl-dev debhelper binutils-dev pkg-config libc6-dev-i386 \
						  lsb-release software-properties-common libpcap-dev zlib1g-dev apt-transport-https \
						  ca-certificates libczmq-dev libprotobuf-c-dev protobuf-c-compiler bison flex cmake \
						  python3-pip libreadline-dev libjson-c-dev

	if ! dpkg -l | grep llvm${LLVM_POSTFIX}; then
		apt-get -f install -y clang${LLVM_POSTFIX} lldb${LLVM_POSTFIX}
		ln -s /usr/bin/clang${LLVM_POSTFIX} /usr/bin/clang
	fi
}

function do_setup() {
	install_packages
}

function do_build() {
	build_dir=$(mktemp -d)
	cd "${build_dir}"
	cmake "${CLONE_DIR}"
	make package
	cp "${build_dir}"/ecbpf*.deb "${CLONE_DIR}"/dist/
}

function do_shell() {
		echo "Skipping build, dropping to shell..."
		exec /bin/bash
}

function usage() {
	echo "Usage: $0 [-s]"
	echo " -i Setup clang repos and install dependencies."
	echo " -s skips build, only sets up environment and drops into a shell."
	echo " -b build."
	exit 0
}

#
# Do a build and install by default
#
while getopts ":hibsdt" opt; do
	case ${opt} in
		i )
		  setup=1
		  ;;
		b )
		  build=1
		  ;;
		s )
		  setup=1 # Setup the shell
		  shell=1
		  ;;
        h )
          usage
		  ;;
        * )
          usage
		  ;;
	  esac
done

[[ -v setup ]] && do_setup
[[ -v shell ]] && do_shell # execs, doesn't return
[[ -v build ]] && do_build

exit 0 # Otherwise we return the result of [[ -v build ]]
