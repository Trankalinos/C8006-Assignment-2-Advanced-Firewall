
################################################################################
################################################################################
##
##      Filename:         ext-firewall.sh
##
##      Author:           David Tran - A00801942 
##			  Cole Rees  - A00741578
##
##      Date:             Thursday, February 20 2014
##
##      Usage:            ./ext-firewall.sh
##
##      Implementation:   Netfilter using $IPT
##
## ---------------------------------------------------------------------------
##
##      Description:      Used as the primary implementation of Assignment 2
##                        in course COMP 8006. The script is designed to set
##                        Netfilter rules using $IPT according to the 
##                        criteria defined in Assignment 2. 
##
##                        The User Defined variables section outlines the 
##                        modifiable ports, type numbers, etc. that the user
##                        may configure. Multiports, and such are commented 
##                        to indicate as such.
##
##                        The Implementation section is strictly off-limits
##                        to the user. If modified, the rulesets may contradict
##                        the requirements of Assignment 2 and can potentially,
##                        severely impact the system. The user will use his/her
##                        discretion when modifying this section. 
##
##                        You have been warned.
##
##
###############################################################################
###############################################################################


############################################################
############## USER DEFINED VARIABLES ######################
############################################################

ALLOWED_TCP="53,67,68,80,443,22,20"                    # based on ports, multiport
ALLOWED_UDP="53,67,68"                              # based on ports, multiport
ALLOWED_ICMP="echo-request,echo-reply"              # based on type number, "multinumber"

INT_ALLOWED_TCP="22,80,20,21"                       # based on ports, multiport
INT_ALLOWED_UDP="53,67,68"                          # based on ports, multiport

SRV_IP="192.168.0.14"
SRV_NET="192.168.0.0/24"
SRV_INTERFACE="em1"

CLNT_IP="192.168.10.2"
CLNT_NET="192.168.10.0/24"
CLNT_INTERFACE="p3p1"

FTP_PASV=0/0

# Tools
IPT=/usr/sbin/iptables

############################################################
############## DFT!! - IMPLEMENTATION ######################
############################################################

/sbin/modprobe ip_conntrack
/sbin/modprobe ip_conntrack_ftp
/sbin/modprobe nf_conntrack
/sbin/modprobe nf_conntrack_ftp
/sbin/modprobe ip_nat_ftp
/sbin/modprobe nf_nat_ftp

# Set IP and Port Forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

# Flush the Tables
$IPT -F
$IPT -X
$IPT -t mangle -F
$IPT -t nat -F
$IPT -t filter -F

# Set default policies
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# User-Defined Chains
$IPT -N tcp-traffic
$IPT -A tcp-traffic
$IPT -N tcp_in
$IPT -N tcp_out
$IPT -A tcp_in
$IPT -A tcp_out

$IPT -N udp-traffic
$IPT -A udp-traffic
$IPT -N udp_in
$IPT -N udp_out
$IPT -A udp_in
$IPT -A udp_out

# Preliminary Traffic Accounting Rules
$IPT -A INPUT -i $SRV_INTERFACE -p tcp -j tcp-traffic
$IPT -A OUTPUT -o $SRV_INTERFACE -p tcp -j tcp-traffic
$IPT -A INPUT -i $CLNT_INTERFACE -p tcp -j tcp-traffic
$IPT -A OUTPUT -o $CLNT_INTERFACE -p tcp -j tcp-traffic

$IPT -A INPUT -i $SRV_INTERFACE -p udp -j udp-traffic
$IPT -A OUTPUT -o $SRV_INTERFACE -p udp -j udp-traffic
$IPT -A INPUT -i $CLNT_INTERFACE -p udp -j udp-traffic
$IPT -A OUTPUT -o $CLNT_INTERFACE -p udp -j udp-traffic

$IPT -A tcp-traffic -i $SRV_INTERFACE -p tcp -j tcp_in
$IPT -A tcp-traffic -o $SRV_INTERFACE -p tcp -j tcp_out
$IPT -A tcp-traffic -i $CLNT_INTERFACE -p tcp -j tcp_in
$IPT -A tcp-traffic -o $CLNT_INTERFACE -p tcp -j tcp_out

$IPT -A udp-traffic -i $SRV_INTERFACE -p udp -j udp_in
$IPT -A udp-traffic -o $SRV_INTERFACE -p udp -j udp_out
$IPT -A udp-traffic -i $CLNT_INTERFACE -p udp -j udp_in
$IPT -A udp-traffic -o $CLNT_INTERFACE -p udp -j udp_out

# Drop stuff destined for the firewall (THIS)
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp -m multiport ! --dports $INT_ALLOWED_TCP -j DROP
$IPT -A udp_in -i $SRV_INTERFACE -p udp -m multiport ! --dports $INT_ALLOWED_UDP -j DROP

# Drop stuff w. source IP that match our internal network
$IPT -A tcp_in -i $SRV_INTERFACE -s $CLNT_NET -p tcp -j DROP
$IPT -A udp_in -i $SRV_INTERFACE -s $CLNT_NET -p udp -j DROP

# Drop all inbound SYN packets unless permitted
# Drop all TCP packets with flags SYN and FIN
# See http://www.smythies.com/~doug/network/$IPT_syn/index.html for details
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -m state --state NEW -j DROP
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp --tcp-flags SYN,FIN SYN,FIN -m state --state NEW -j DROP
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp --tcp-flags SYN,RST SYN,RST -m state --state NEW -j DROP

$IPT -A tcp_out -o $SRV_INTERFACE -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A tcp_out -o $SRV_INTERFACE -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -m state --state NEW -j DROP
$IPT -A tcp_out -o $SRV_INTERFACE -p tcp --tcp-flags SYN,FIN SYN,FIN -m state --state NEW -j DROP
$IPT -A tcp_out -o $SRV_INTERFACE -p tcp --tcp-flags SYN,RST SYN,RST -m state --state NEW -j DROP

# Drop all traffic on telnet (TCP port:23)
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp --dport 23 -j DROP
$IPT -A tcp_out -i $SRV_INTERFACE -p tcp --sport 23 -j DROP
$IPT -A tcp_in -i $CLNT_INTERFACE -p tcp --dport 23 -j DROP
$IPT -A tcp_out -i $CLNT_INTERFACE -p tcp --sport 23 -j DROP

# Drop all external traffic directed to ports:
# 32768-32775, 137-139, and TCP ports 111 and 515
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp -m multiport --dport 32768:32775,137:139,111,515 -j DROP
$IPT -A udp_in -i $SRV_INTERFACE -p udp -m multiport --dport 32768:32775,137:139 -j DROP

# Accept incoming fragments
$IPT -A tcp_in -i $SRV_INTERFACE -f -m state --state ESTABLISHED -j ACCEPT
$IPT -A tcp_in -i $CLNT_INTERFACE -f -m state --state ESTABLISHED -j ACCEPT
$IPT -A udp_in -i $SRV_INTERFACE -f -m state --state ESTABLISHED -j ACCEPT
$IPT -A udp_in -i $CLNT_INTERFACE -f -m state --state ESTABLISHED -j ACCEPT

# Set control connection for FTP and SSH to "Minimum Delay"
# Set control connection for FTP to "Maximum Throughput"
$IPT -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay
$IPT -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay
$IPT -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput

# Inbound / Outbound permitted on these ports (TCP)
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp -m multiport --sport $ALLOWED_TCP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A tcp_out -o $SRV_INTERFACE -p tcp -m multiport --sport $ALLOWED_TCP -m state --state ESTABLISHED -j ACCEPT
$IPT -A tcp_in -i $SRV_INTERFACE -p tcp -m multiport --dport $ALLOWED_TCP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A tcp_out -o $SRV_INTERFACE -p tcp -m multiport --dport $ALLOWED_TCP -m state --state ESTABLISHED -j ACCEPT

$IPT -A tcp_in -i $CLNT_INTERFACE -p tcp -m multiport --sport $ALLOWED_TCP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A tcp_out -o $CLNT_INTERFACE -p tcp -m multiport --sport $ALLOWED_TCP -m state --state ESTABLISHED -j ACCEPT
$IPT -A tcp_in -i $CLNT_INTERFACE -p tcp -m multiport --dport $ALLOWED_TCP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A tcp_out -o $CLNT_INTERFACE -p tcp -m multiport --dport $ALLOWED_TCP -m state --state ESTABLISHED -j ACCEPT

# Inbound / Outbound permitted on these ports (UDP)
$IPT -A udp_in -i $SRV_INTERFACE -p udp -m multiport --sport $ALLOWED_UDP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A udp_out -o $SRV_INTERFACE -p udp -m multiport --sport $ALLOWED_UDP -m state --state ESTABLISHED -j ACCEPT
$IPT -A udp_in -i $SRV_INTERFACE -p udp -m multiport --dport $ALLOWED_UDP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A udp_out -o $SRV_INTERFACE -p udp -m multiport --dport $ALLOWED_UDP -m state --state ESTABLISHED -j ACCEPT

$IPT -A udp_in -i $CLNT_INTERFACE -p udp -m multiport --sport $ALLOWED_UDP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A udp_out -o $CLNT_INTERFACE -p udp -m multiport --sport $ALLOWED_UDP -m state --state ESTABLISHED -j ACCEPT
$IPT -A udp_in -i $CLNT_INTERFACE -p udp -m multiport --dport $ALLOWED_UDP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A udp_out -o $CLNT_INTERFACE -p udp -m multiport --dport $ALLOWED_UDP -m state --state ESTABLISHED -j ACCEPT

# Inbound / Outbound permitted on these type numbers (ICMP)
icmp=$(echo $ALLOWED_ICMP | tr "," "\n")
for x in $icmp
do
	$IPT -A INPUT -i $SRV_INTERFACE -p icmp -m icmp --icmp-type $x -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i $CLNT_INTERFACE -p icmp -m icmp --icmp-type $x -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A OUTPUT -o $SRV_INTERFACE -p icmp -m icmp --icmp-type $x -m state --state ESTABLISHED -j ACCEPT
	$IPT -A OUTPUT -o $CLNT_INTERFACE -p icmp -m icmp --icmp-type $x -m state --state ESTABLISHED -j ACCEPT
done

# IP Forwarding
$IPT -t nat -A POSTROUTING -o $SRV_INTERFACE -j SNAT --to $SRV_IP
$IPT -t nat -A PREROUTING -i $SRV_INTERFACE -p tcp -m multiport --dports $INT_ALLOWED_TCP -j DNAT --to-destination $CLNT_IP
$IPT -t nat -A PREROUTING -i $SRV_INTERFACE -p udp -m multiport --dports $INT_ALLOWED_UDP -j DNAT --to-destination $CLNT_IP
$IPT -A FORWARD -i $SRV_INTERFACE -o $CLNT_INTERFACE -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A FORWARD -i $CLNT_INTERFACE -o $SRV_INTERFACE -m state --state NEW,ESTABLISHED -j ACCEPT

# save, restart, and check the $IPT
service $IPT save
service $IPT restart
$IPT -L -n -v -x
