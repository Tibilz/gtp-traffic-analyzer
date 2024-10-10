# nice to know
Linux distro: lsb_release -a
Check system architecture: uname -i
Check Linux kernel version: uname -r

AVX supported by CPU (empty if not): lscpu | grep avx

Show Network Interfaces: ip a

Add IPv4-Adress for interface: sudo ip addr add <IPv4, suitable for subnet> dev <Interface name: upfgtp>
Make it persistent: sudo nano /etc/netplan/00-installer-config.yaml
-> add under "ethernets:" :
    upfgtp:
      addresses:
        - 10.2.3.1/24"
-> sudo netplan apply


# iperf bandwidth test
On kom_nfv: iperf3 -s
On kom_tg: iperf3 -c 10.2.2.157

# wireshark (tshark for desktopless environments)
Install: sudo apt install tshark  
On NFV: sudo tshark -i ens18 -Y "gtp"
sudo tshark -i ens18 -Y "gtp.message == 255 && ip.src == 10.2.2.154"

