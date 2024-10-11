Setup:
Tested on : Ubuntu 22.04.6 (NFV), Ubuntu 22.04.4 (TG)

1. Download OVS (switched to raw sockets):
https://docs.openvswitch.org/en/latest/intro/install/general/#obtaining-open-vswitch-sources
1a. Clone Git repo: git clone https://github.com/openvswitch/ovs.git (19.06.23)


    1b. as .deb package
Tested on : 2.17.9-0  ubuntu0.22.04.1
https://docs.openvswitch.org/en/latest/intro/install/distributions/#debian-ubuntu
sudo apt install openvswitch-switch

2. Install free5GC 
free5GC from scratch
https://free5gc.org/guide/#advanced-build-free5gc-from-scratch
-> In order to use the UPF element, you must use the 5.0.0-23-generic or 5.4.x version of the Linux kernel (check with "uname -r")
-> Check Ubuntu version with "lsb_release -a" 
Check if AVX is supported by CPU: lscpu | grep avx
-> If output empty, its not supported

3. Install iperf
Tested on : 3.9-1+deb11u1build0.22.04.1
sudo apt-get install iperf3

4. Configure everything
On NFV: Mainly amfcfg.yaml, smfcfg.yaml, upfcfg.yaml
-> after that, install webconsole according to free5GC tutorial and add a Subscriber
On TG: install PacketRusher, setup config.yaml (according to Subscriber in webconsole)

5. Test setup with iperf
See cheatsheet (iperf bandwidth test)

6. Setup ipv4 for upfgtp
sudo ip addr add 10.2.3.1/24 dev upfgtp
add to upfcfg.yaml?

7. Check protocolstack and gptu packet structure (use ip adress from 6.)