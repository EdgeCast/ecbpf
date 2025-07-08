#!/bin/sh

ctags --recurse=yes --exclude=.git --exclude="build/*" --exclude=ext/libbpf/.github
