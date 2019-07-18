![GitHub release](https://img.shields.io/github/release/worldstream-labs/check_powerdns_auth.svg) 
![GitHub](https://img.shields.io/github/license/worldstream-labs/check_powerdns_auth.svg?color=blue) 
![python 3](https://img.shields.io/badge/python-3-blue.svg)

# PowerDNS Authoritative check

Icinga/Nagios plugin, interned to check PowerDNS status using pdns_control.
A non-zero exit code is generated, if the numbers of DNS queries per seconds exceeds
warning/critical

## Installation and requirements

*   Python 2.7
*   [pdns_control](https://doc.powerdns.com/authoritative/manpages/pdns_control.1.html)
    pdns_control is included in the PowerDNS package. It is used to send commands to a running PowerDNS nameserver.
*   [monitoring-plugins](https://github.com/monitoring-plugins/monitoring-plugins)
    On debian-based systems you need the package `nagios-plugins` or the package `monitoring-plugins`


## Usage
	usage: check_powerdns_auth.py [-h] [-S SOCKET_DIR] [-n CONFIG_NAME]
                              [-w WARNING] [-c CRITICAL] [-s SCRATCH] [-p]
                              [--skipsecurity] [-T] [-V]

	-h, --help            show this help message and exit
	-S SOCKET_DIR, --socket-dir SOCKET_DIR
	                      Where the PowerDNS controlsocket will live
	-n CONFIG_NAME, --config-name CONFIG_NAME
	                      Name of PowerDNS virtual configuration
	-w WARNING, --warning WARNING
	                      Warning threshold (Queries/s)
	-c CRITICAL, --critical CRITICAL
	                      Critical threshold (Queries/s)
	-s SCRATCH, --scratch SCRATCH
	                      Scratch / temp base directory. Must exist. (default: /tmp)
	-p, --perfdata        Print performance data, (default: off)
	--skipsecurity        Skip PowerDNS security status, (default: off)
	-T, --test            Test case; Use fake data and do not run pdns_control
	-V, --version         show program's version number and exit

## License

PowerDNS Authoritative check is licensed under the terms of the GNU
General Public License Version 3.
