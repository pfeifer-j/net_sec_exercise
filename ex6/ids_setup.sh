#!/bin/bash

# Add PPA
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
# Install Zeek Core
sudo apt update
sudo apt install zeek-lts-core --no-install-recommends

# Link under PATH
sudo ln -s /opt/zeek/bin/zeek /usr/local/bin/zeek
sudo ln -s /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
# Allow non-root
#sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek
