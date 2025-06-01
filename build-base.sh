#!/bin/bash
set -ex
OPENRESTYVER=1.25.3.2
cd $(dirname $0)

sed -i "s/deb.debian.org/${MIRROR}/g" /etc/apt/sources.list.d/debian.sources

apt update && apt upgrade -y
apt install -y zlib1g-dev libperl-dev libpcre3-dev libssl-dev libffi-dev wget gcc g++ make iperf3
apt install -y supervisor redis python3 python3-dev python3-pip

mkdir -p ${HOME}

pushd $(pwd)
# openresty
pushd $(pwd)
cat openresty-1.25.3.2.tar.gz | tar -xz
cd openresty-${OPENRESTYVER} && ./configure --with-http_v2_module && make -j8 install
popd

cat lua-resty-http-v0.17.2.tar.gz | tar -xz
cp -pr lua-resty-http-0.17.2/lib/resty/http*.lua /usr/local/openresty/lualib/resty
cat lua-resty-openssl-1.2.1.tar.gz | tar -xz
cp -pr lua-resty-openssl-1.2.1/lib/resty/* /usr/local/openresty/lualib/resty
popd