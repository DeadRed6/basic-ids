This is a program that sniffs packets on an interface and returns the following metrics when terminated:
- Number of SYN packets detected and the number of unique IPs (SYN Attack)
- Number of unsolicited ARP reply/response packets (ARP Cache Poisoning)
- Number of HTTP URL Blocklist violations
- Number of packets seen

Installation:
`make` - which creates `../build/`
`../build/idsniff` - which runs the project with default options. May require root.

Prerequisites:
`libpcap_devel` at a minimum. gcc will tell you if you're missing a dependency. Use your distro's package manager.

Note:
On some Linux systems, their endianness will affect the names of the fields in various structs, most notably affecting `<netinet/if_ether.h>` and `<netinet/tcp.h>`. In this case, some adjustments will need to be made to `analysis.c` to correctly access the various packet headers.
