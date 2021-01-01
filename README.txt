Installation:
`make` - which creates `../build/`
`../build/idsniff` - which runs the project with default options. May require root.

Prerequisites:
`libpcap_devel` at a minimum. gcc will tell you if you're missing a dependency. Use your distro's package manager.

Note:
On some Linux systems, their endianness will affect the names of the fields in various structs, most notably affecting `<netinet/if_ether.h>` and `<netinet/tcp.h>`. In this case, some adjustments will need to be made to `analysis.c` to correctly access the various packet headers.