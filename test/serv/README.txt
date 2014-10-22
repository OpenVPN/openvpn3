OpenVPN 3 Test Server

Build on Mac:

  GCC_EXTRA="-ferror-limit=4" PSSL=1 SNAP=1 LZ4=1 build serv

Connect client/server via localhost (IPv4):

  ./serv $O3S/serv.ovpn
  ../ovpncli/cli -t 5 $O3S/cli.ovpn

Connect client/server via localhost (IPv6):

  ./serv $O3S/serv6.ovpn
  ../ovpncli/cli -t 5 $O3S/cli6.ovpn
