#!/bin/bash
#
##################################################################################################################
# FIREWALL SAMPLE
##################################################################################################################

##################################################################################################################
# VARIABLES OF NETWORK
##################################################################################################################
IPT=$(which iptables)
MODPROBE=$(which modprobe)

IF_LOC="lo"
NET_LOC="127.0.0.1/8"

IF_WAN="eth0" # Interface PaP with Datacenter
IP_WAN="20.0.0.2" # IF_WAN
NET_WAN="20.0.0.0" # Network from interface IF_WAN
BRO_WAN="20.0.0.15" # Broadcast from interface IF_WAN

IF_SER="eth1" # Interface for Servers
IP_SER="192.168.0.60" # IP
NET_SER="192.168.0.0/26" # Network from interface IF_SER
BRO_SER="192.168.0.63" # Broadcast from interface IF_SER

IF_TEL="eth2" # Interface of VoIP network
IP_TEL="192.168.111.10" # IP IF_TEL
NET_TEL="192.168.111.0/25" # Network from interface IF_TEL
BRO_TEL="192.168.111.127" # Broadcast from interface IF_TEL

IF_RL="eth3" # Interface of local network
IP_RL="192.168.222.30" # IP from interface IF_RL
NET_RL="192.168.222.0/25" # Network from interface IF_RL
BRO_RL="192.168.222.127" # Broadcast from interface IF_RL

###################################################################################################################
# VARIABLES FROM SERVERS
###################################################################################################################
IP_PROXY="192.168.222.30" # IP proxy
IP_DNS1="192.168.0.18" # DNS 1
IP_DNS2="192.168.0.19" # DNS 2
IP_ZABBIX="192.168.0.55" # Monitoring Server Zabbix
IP_RL_DIR="192.168.3.1/24" # VLAN Managers
IP_BD1="192.168.0.5" # DB Master
IP_BD2="192.168.0.6" # DB Slave
IP_IM="192.168.0.14" # IM Server
IP_WEB="192.168.0.8" # Intranet Server
IP_WIRE="192.168.222.116" # Router Wireless

IP_ESX1="192.168.0.25"
IP_ESX2="192.168.0.26"
IP_PDC="192.168.0.9"
IPE_DNS1="200.219.204.56" # DNS 1
IPE_DNS2="200.219.204.55" # DNS 2
IPE_SMTP="200.234.205.135" # SMTP
IPE_POP="200.234.205.135" # POP


function modules()
{
    echo "Carregando os módulos"
    $MODPROBE ip_tables
    $MODPROBE iptable_filter
    $MODPROBE ip_conntrack
    $MODPROBE ip_conntrack_ftp
    $MODPROBE ip_nat_ftp
    $MODPROBE ip_nat_sip
    $MODPROBE ip_conntrack_sip
    echo 1 > /proc/sys/net/ipv4/ip_forward
}

function flush()
{
    echo "Cleaning up the firewall rules..."
    $IPT -F
    $IPT -F -t filter
    $IPT -F -t nat
    $IPT -F -t mangle
}

function acceptall()
{
    echo "Open firewall"
    echo "WARNING: From now the iptables will not block the malicious request"
    $IPT -F
    $IPT -F -t filter
    $IPT -F -t nat
    $IPT -F -t mangle

    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
}

function block()
{
    echo "Blocking the firewall"
    $IPT -P INPUT DROP
    $IPT -P OUTPUT DROP
    $IPT -P FORWARD DROP
}

function rules()
{
    echo "Computers from internal network accessing proxy"
    $IPT -A INPUT -p tcp -s $NET_RL --sport 1024:65535 -d $IP_PROXY --dport 8889 -j ACCEPT
    $IPT -A INPUT -p tcp -s $NET_RL --sport 1024:65535 -d $IP_PROXY --dport 8889 -j ACCEPT

    $IPT -A OUTPUT -p tcp -s $IP_PROXY --sport 8889 -d $NET_RL --sport 1024:65535 -j ACCEPT
    $IPT -A OUTPUT -p tcp -s $IP_PROXY --sport 8889 -d $NET_RL --sport 1024:65535 -j ACCEPT

    echo "Accepting loopback interface"
    $IPT -A INPUT -i lo -d $IF_LOC -j ACCEPT
    $IPT -A OUTPUT -o lo -d $IF_LOC -j ACCEPT

    echo "Protection against port scanners"
    $IPT -N SCANNER
    $IPT -A SCANNER -m limit --limit 15/m -j LOG --log-prefix "FIREWALL: port scanner: "
    $IPT -A SCANNER -j DROP
    $IPT -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -i $IF_WAN -j SCANNER
    $IPT -A INPUT -p tcp --tcp-flags ALL NONE -i $IF_WAN -j SCANNER
    $IPT -A INPUT -p tcp --tcp-flags ALL ALL -i $IF_WAN -j SCANNER
    $IPT -A INPUT -p tcp --tcp-flags ALL FIN,SYN -i $IF_WAN -j SCANNER
    $IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -i $IF_WAN -j SCANNER
    $IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i $IF_WAN -j SCANNER
    $IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i $IF_WAN -j SCANNER

    echo "Lie to port scanners"
    $IPT -A INPUT -p tcp --dport 1433 -j DROP
    $IPT -A INPUT -p tcp --dport 6670 -j DROP
    $IPT -A INPUT -p tcp --dport 6711 -j DROP
    $IPT -A INPUT -p tcp --dport 6712 -j REJECT
    $IPT -A INPUT -p tcp --dport 6713 -j REJECT
    $IPT -A INPUT -p tcp --dport 12345 -j REJECT
    $IPT -A INPUT -p tcp --dport 12346 -j REJECT --tcp-reset
    $IPT -A INPUT -p tcp --dport 20034 -j REJECT --tcp-reset
    $IPT -A INPUT -p tcp --dport 31337 -j REJECT --tcp-reset
    $IPT -A INPUT -p tcp --dport 6000 -j REJECT --tcp-reset

    echo "Doesnt pass through firewall"
    $IPT -A INPUT -s 192.168.222.116 -j ACCEPT
    $IPT -A OUTPUT -s 192.168.222.116 -j ACCEPT

    $IPT -A INPUT -s 192.168.3.0/24 -j ACCEPT
    $IPT -A OUTPUT -s 192.168.3.0/24 -j ACCEPT

    echo "Protection against external access of proxy"
    $IPT -A INPUT -i $IF_WAN -s 0/0 -d $IP_PROXY --dport 8889 -j DROP

    echo "Allow remote access by PcAnywhere"
    $IPT -A OUTPUT -s $NET_RL --sport 1024:65535 -d 0/0 --dport 5631 -j ACCEPT
    $IPT -A INPUT -s 0/0 --sport 5631 -d $NET_RL --dport 1024:65535 -j ACCEPT

    echo "Allow remote access by Remote Desktop"
    $IPT -A OUTPUT -s $NET_RL --sport 1024:65535 -d 0/0 --dport 3389 -j ACCEPT
    $IPT -A INPUT -s 0/0 --sport 3389 -d $NET_RL --dport 1024:65535 -j ACCEPT

    echo "Allow remote access by telnet and VNC"
    $IPT -A OUTPUT -s $NET_RL --sport 1024:65535 -d 0/0 --dport 23 -j ACCEPT
    $IPT -A INPUT -s 0/0 --sport 23 -d $NET_RL --dport 1024:65535 -j ACCEPT

    echo "Allow Zabbix monitoring"
    $IPT -A INPUT -d $IP_SER --dport 10050 -s $IP_ZABBIX --sport 1024:65535 -j ACCEPT
    $IPT -A OUTPUT -d $IP_ZABBIX --dport 1024:65535 -s $IP_SER --sport 10050 -j ACCEPT

    echo "Allow access of SSH to Internet, servers and local network"
    $IPT -A INPUT -s $NET_RL --sport 1024:65535 -d 0/0 -m multiport --dport 22,60782 -j ACCEPT
    $IPT -A OUTPUT -s 0/0 -m multiport --sport 22,60782 -d $NET_RL --dport 1024:65535 -j ACCEPT

    echo "Allow ICMP type 8 and 0"
    $IPT -A OUPUT -s 0/0 -d 0/0 -p icmp --icmp-type 8 -m limit --limit 1/s -j ACCEPT
    $IPT -A INPUT -s 0/0 -d 0/0 -p icmp --icmp-type 0 -m limit --limit 1/s -j ACCEPT

    echo "Allow ICMP type traceroute"
    $IPT -A INPUT -s 0/0 -d 0/0 -p icmp --icmp-type 11 -m limit --limit 1/s -j ACCEPT

    echo "DNS 1 for internal network"
    $IPT -A INPUT -s $NET_RL --sport 1024:65535 -p udp -d 200.219.204.56 --dport 53 -j ACCEPT
    $IPT -A OUTPUT -s 200.219.204.56 -sport 53 -p udp -d $NET_RL --dport 1024:65535 -j ACCEPT

    echo "DNS 2 for internal network"
    $IPT -A INPUT -s $NET_RL --sport 1024:65535 -p udp -d 200.219.204.55 --dport 53 -j ACCEPT
    $IPT -A OUTPUT -s 200.219.204.55 -sport 53 -p udp -d $NET_RL --dport 1024:65535 -j ACCEPT

    echo "Allow my own navigation"
    $IPT -A OUTPUT -s $IP_PROXY --sport 1024:65535 -p tcp -d 0/0 --dport 80 -j ACCEPT
    $IPT -A OUTPUT -s $IP_PROXY --sport 1024:65535 -p tcp -d 0/0 --dport 443 -j ACCEPT

    $IPT -A INPUT -s 0/0 --sport 80 -p tcp -d $IP_PROXY --dport 1024:65535 -j ACCEPT
    $IPT -A INPUT -s 0/0 --sport 443 -p tcp -d $IP_PROXY --dport 1024:65535 -j ACCEPT

    echo "Creating chain from internal network to Internet"
    $IPT -N RL_INT

    echo "Allow sent emails"
    $IPT -A RL_INT -s smtp.locaweb.com.br -p tcp --dport 25 -j ACCEPT

    echo "Allow access to local web server"
    $IPT -A RL_INT -s $IP_WEB -j REJECT --tcp-reset ACCEPT

    echo "Allow access to local IM Server"
    $IPT -A RL_INT -p tcp --dport 5222 -s $IP_IM -j ACCEPT

    echo "Allow access to local DB"
    $IPT -A RL_INT -p tcp --dport 3306 -s $IP_BD1 -j ACCEPT
    $IPT -A RL_INT -p tcp --dport 3306 -s $IP_BD2 -j ACCEPT

    echo "Allow access to VMware ESX"
    $IPT -A RL_INT -p tcp --dport 902 -s $IP_VM1 -j ACCEPT
    $IPT -A RL_INT -p tcp --dport 902 -s $IP_VM2 -j ACCEPT

    echo "Allow communication between VLAN of computers and phones"
    $IPT -A RL_INT -s $NET_RL -d $NET_TEL -j ACCEPT

    echo "Enable log"
    $IPT -A RL_INT -j LOG --log-prefix "Firewall: RL_INT -> "

    echo "Drop remain packages"
    $IPT -A RL_INT -j DROP

    echo "Creating chain from Internet to local network"
    $IPT -N INT_RL

    echo "Incomming emails"
    $IPT -A INT_RL -p tcp -m multiport --dport 25,110 -d $NET_RL -j ACCEPT

    echo "DNS Server"
    $IPT -A INT_RL -p udp --dport 53 -d $IP_DNS1 -j ACCEPT
    $IPT -A INT_RL -p udp --dport 53 -d $IP_DNS2 -j ACCEPT

    echo "Incoming VPN"
    $IPT -A INT_RL -p udp --dport 1194 -d $IP_VPN -j ACCEPT

    echo "Enable LOG"
    $IPT -A INT_RL -j LOG

    echo "Drop remain packages"
    $IPT -A INT_RL -j DROP

    echo "Blocking by layer 7"
    $IPT -A FORWARD -s $NET_RL -d 0/0 -j DROP
    $IPT -A FORWARD -s $NET_RL -d 0/0 -j DROP
    $IPT -A FORWARD -s $NET_RL -d 0/0 -j DROP
    $IPT -A FORWARD -s $NET_RL -d 0/0 -j DROP
    $IPT -A FORWARD -s $NET_RL -d 0/0 -j DROP

    echo "Forward by the specific chain"
    $IPT -A FORWARD -s $NET_RL -d 0/0 -j RL_INT
    $IPT -A FORWARD -s 0/0 -d $NET_RL -j INT_RL

    $IPT -A FORWARD -s $NET_TEL -d 0/0 -j RL_INT

    $IPT -A FORWARD -s 0/0 -d $NET_TEL -j INT_RL

    echo "Applying NAT rules"
    $IPT -A POSTROUTING -t nat -s $IP_RL_DIR -j SNAT --to 20.0.0.2 -o eth0
    $IPT -A POSTROUTING -t nat -s $IP_RL_INT -j SNAT --to $IP_WAN -o $IF_WAN

    echo "DNS 1 incomming"
    $IPT -A PREROUTING -t nat -d $IPE_DNS1 -p udp --dport 53 -j DNAT --to $IP_DNS1

    echo "DNS 2 incomming"
    $IPT -A PREROUTING -t nat -d $IPE_DNS2 -p udp --dport 53 -j DNAT --to $IP_DNS2

    $IPT -t nat -A PREROUTING -s 0/0 --sport 1024:65535 -p tcp -d $IP_PROXY --dport 5222 -j DNAT --to $IP_IM:5222

    echo "Redirect to Server IM"
    $IPT -t nat -A PREROUTING -d $IP_WAN -p tcp --dport 5222 -j DNAT --to $IP_IM:5222

    echo "Modifying TTL"
    #$IPT -A OUTPUT -m ttl --ttl-eq 128
    $IPT -t mangle -A PREROUTING -i $IF_WAN -j TTL --ttl-set 128
}

function establishing()
{
    echo "Establishing connections of input"
    $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPT -A INPUT -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "NEW NOT SYN:"

    echo "Establishing connections of output"
    $IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "Establishing connections of forward"
    $IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPT -A FORWARD -m state --state NEW -j ACCEPT
}

function unclean()
{
    echo "Drop malformated packages"
    $IPT -A INPUT -i $internet -m unclean -j DROP
}

case $1 in
    start)
	flush
	block
	establishing
	rules
	echo "Firewall actived"
	;;
    stop)
	flush
	acceptall
	echo "Firewall deactivated"
	;;
    filter) $IPT -nL | more
	    ;;
    nat) $IPT -nL -t nat | more
	 ;;
    mangle) $IPT -nL -t mangle | more
	    ;;
    restart) $0 stop
	     $0 start
	     ;;
    *) echo "erro use $0 {start|stop|filter|nat|mangle|restart}"
       exit 0
