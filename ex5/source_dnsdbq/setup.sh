#!/bin/bash

sudo apt-get -y install git make gcc libcurl4-openssl-dev libjansson-dev

git clone --branch v2.3.0 https://github.com/dnsdb/dnsdbq.git
cd dnsdbq
sudo make install clean
