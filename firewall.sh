#!/bin/sh 

PATH="/sbin:/usr/sbin:/bin:/usr/bin:${PATH}"
export PATH

### Variables global
	MODPROBE="/usr/bin/modprobe"
	IPTABLES="/usr/bin/iptables"
	IPTABLES_SAVE="/usr/bin/iptables-save"
	SYSTEMCTL="/usr/bin/systemctl"
	IPTABLES_RULES="/etc/iptables/iptables.rules"

### Load config
	if [[ -f /etc/firewall.conf ]]; then
		source /etc/firewall.conf
	else
		echo "File \"/etc/firewall.conf\" not found. Aborted."
		exit 1
	fi

### Load modules
	$MODPROBE ip_tables
	$MODPROBE iptable_nat
	$MODPROBE iptable_filter
	$MODPROBE ip_conntrack
	$MODPROBE ip_conntrack_ftp
	# $MODPROBE nf_conntrack_ipv4
	$MODPROBE ip_nat_ftp
	$MODPROBE ipt_MASQUERADE
	$MODPROBE iptable_mangle
	$MODPROBE nf_nat
	$MODPROBE nf_conntrack
	$MODPROBE x_tables
	$MODPROBE nf_nat_pptp


### Clean rules and disable Iptables
	function _off () {
	### Clean
		$IPTABLES -F
		$IPTABLES -X
		$IPTABLES -t nat -F
		$IPTABLES -t nat -X
		$IPTABLES -t mangle -F
		$IPTABLES -t mangle -X
		$IPTABLES -t raw -F
		$IPTABLES -t raw -X
		$IPTABLES -t security -F
		$IPTABLES -t security -X
	### Reset IPTables to all ACCEPT
		$IPTABLES -P INPUT ACCEPT
		$IPTABLES -P OUTPUT ACCEPT
		$IPTABLES -P FORWARD ACCEPT
	}


### Start
	function _on () {
	### Defaults
		$IPTABLES -P INPUT DROP
		$IPTABLES -P FORWARD DROP
		$IPTABLES -P OUTPUT ACCEPT

	# Keep connections open
	    $IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	    $IPTABLES -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	    $IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
		
	### Loopback
	    # Allow loopback
	    # $IPTABLES -A INPUT -i lo -j ACCEPT
	    # $IPTABLES -A OUTPUT -o lo -j ACCEPT
	    $IPTABLES -A INPUT -i lo -m state --state NEW  -j ACCEPT
	    $IPTABLES -A OUTPUT -o lo -m state --state NEW  -j ACCEPT

	### Security (https://wiki.archlinux.org/title/simple_stateful_firewall)
		$IPTABLES -N TCP
		$IPTABLES -N UDP
		$IPTABLES -A INPUT -p icmp -j ACCEPT
		$IPTABLES -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP
		$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
		$IPTABLES -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
		$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j TCP
		$IPTABLES -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
		$IPTABLES -A INPUT -p tcp -j REJECT --reject-with tcp-reset
		$IPTABLES -A INPUT -j REJECT --reject-with icmp-proto-unreachable
		# # Bruteforce attacks
		$IPTABLES -N IN_SSH
		$IPTABLES -N LOG_AND_DROP
		$IPTABLES -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -j IN_SSH
		$IPTABLES -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 3 --seconds 10 -j LOG_AND_DROP
		$IPTABLES -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 4 --seconds 1800 -j LOG_AND_DROP
		$IPTABLES -A IN_SSH -m recent --name sshbf --set -j ACCEPT
		$IPTABLES -A LOG_AND_DROP -j LOG --log-prefix "iptables deny: " --log-level 7
		$IPTABLES -A LOG_AND_DROP -j DROP

	### Transmission access
		$IPTABLES -A OUTPUT -p udp --sport 1900 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp --dport 51413 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp --sport 51413 -j ACCEPT
		$IPTABLES -A OUTPUT -p tcp --dport 51413 -j ACCEPT

	### Steam access
		$IPTABLES -A OUTPUT -p udp --dport 3478 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp --dport 4379 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp --dport 4380 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp --dport 27000:27050 -j ACCEPT
		$IPTABLES -A OUTPUT -p tcp --dport 27000:27050 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp --dport 4380 -j ACCEPT

	### Masquerade network
		if [[ $MASQUERADE_ENABLE == "y" ]] && [[ $IF_PRV ]]; then
			echo 1 > /proc/sys/net/ipv4/ip_forward
			echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
			$IPTABLES -t nat -A POSTROUTING -o $IF_PRV -j MASQUERADE
		fi

	### Squid
		### In server (machine local)
			if [[ $SQUID_SERVER_ENABLE == "y" ]]; then
				$IPTABLES -t nat -N SQUID_IN_SERVER
				$IPTABLES -t nat -A SQUID_IN_SERVER -m multiport -p tcp --dports 80,443,$SQUID_PORT_I,$SQUID_PORT_IS -m owner --uid-owner $SQUID_GROUP -j ACCEPT
				$IPTABLES -t nat -A SQUID_IN_SERVER -p tcp --dport 80 -j REDIRECT --to-port $SQUID_PORT_I
				$IPTABLES -t nat -A SQUID_IN_SERVER -p tcp --dport 443 -j REDIRECT --to-port $SQUID_PORT_IS
				## redirect by IP
				# $IPTABLES -t nat -A SQUID_IN_SERVER -p tcp --dport 80 -j DNAT --to-destination $IP_PRV:$SQUID_PORT_I
				# $IPTABLES -t nat -A SQUID_IN_SERVER -p tcp --dport 443 -j DNAT --to-destination $IP_PRV:$SQUID_PORT_IS
				$IPTABLES -t nat -A OUTPUT -j SQUID_IN_SERVER
			fi

		### On the network
			if [[ $SQUID_NETWORK_ENABLE == "y" ]]; then
				$IPTABLES -t nat -N SQUID_NETWORK
				# Accept traffic to redirected ports 3128, 3129 and proxy port 3130
				if [[ ! -z $IF_PUB ]]; then
					$IPTABLES -N SQUID_INPUT
					$IPTABLES -A SQUID_INPUT -i $IF_PUB -m multiport -p tcp --dports $SQUID_PORT,$SQUID_PORT_I,$SQUID_PORT_IS -j ACCEPT
					$IPTABLES -A INPUT -j SQUID_INPUT
				fi
				# Redirect HTTP to locally installed Squid instance
				$IPTABLES -t nat -A SQUID_NETWORK -p tcp -i $IF_PRV --dport 80 -j REDIRECT --to-port $SQUID_PORT_I
				# Redirect HTTPS to locally installed Squid instance
				$IPTABLES -t nat -A SQUID_NETWORK  -p tcp -i $IF_PRV --dport 443 -j REDIRECT --to-port $SQUID_PORT_IS
				$IPTABLES -t nat -A PREROUTING -j SQUID_NETWORK
			fi

	 	### Accept traffic to redirected ports 3128,3129 and proxy port 3130
	 	if [[ $SQUID_NETWORK_ENABLE == "y" ]] || [[ $SQUID_SERVER_ENABLE == "y" ]]; then
			$IPTABLES -A FORWARD -m state --state NEW,ESTABLISHED,RELATED -m multiport -p tcp --dports $SQUID_PORT_I,$SQUID_PORT_IS -j ACCEPT
		fi
		
	### Drop invalid
		$IPTABLES -N drop_invalid 
		$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID  -j drop_invalid
		$IPTABLES -A drop_invalid -j LOG --log-level info --log-prefix "drop_invalid -- DENY "
		$IPTABLES -A drop_invalid -j DROP
		$IPTABLES -A OUTPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK,PSH,URG SYN -m state --state NEW -j DROP


	### Begin - PUT YOUR OTHER RULES HERE

	### End - PUT YOUR OTHER RULES HERE

	### Logs
		$IPTABLES -A INPUT -j LOG --log-prefix "Input-Dropped: "

}


function _save () {
	### Save
		$IPTABLES_SAVE > $IPTABLES_RULES
		$SYSTEMCTL restart iptables.service
}


### Options
	case $1 in
		off)
			_off
			_save
		;;
		squid)
			case $2 in
				off)
					[[ $SQUID_SERVER_ENABLE == "y" ]] && $IPTABLES -t nat -D OUTPUT -j SQUID_IN_SERVER
					[[ $SQUID_NETWORK_ENABLE == "y" ]] && $IPTABLES -t nat -D PREROUTING -j SQUID_NETWORK
					_save

				;;
				on)
					[[ $SQUID_SERVER_ENABLE == "y" ]] && $IPTABLES -t nat -A OUTPUT -j SQUID_IN_SERVER
					[[ $SQUID_NETWORK_ENABLE == "y" ]] && $IPTABLES -t nat -A PREROUTING -j SQUID_NETWORK
					_save
				;;
				*)
					echo "Use: { on | off }"
				;;
			esac
		;;
		on)
			_off
			_on
			_save
		;;
		*)
			echo "Use: { on | off | squid }"
		;;
	esac
	exit 0
