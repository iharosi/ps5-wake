PlayStation 5 Discovery and Wake-up Utility
===========================================
Original [ps4-wake](https://github.com/venkatarajasekhar/ps4-wake) code by Darryl Sokoloski <darryl@sokoloski.ca>

Requirements
------------
In order to wake your PS5 remotely, the PS5 must be in Standby mode.

If you just wish to see the current status of your PS5, you do not require a „user credential” number.

For wake-up support, you need to obtain a „user credential” which requires PS Remote Play app that has already been paired with PS5. You then need to capture and examine the initial few UDP packets sent from the app when launching PS5-xxx. Under Unix-like (Linux, BSD, OSX) operating systems you can use tcpdump or Wireshark. The traffic must be captured from your home network's gateway in order to see these packets.

An example capture using tcpdump:

    # tcpdump -s0 -X -n -i <interface> udp and port 9302

You'll be looking for a packet that looks like HTTP and contains the string 'user-credential:-NNNNNNN'. Remember the „user credential” number.

Usage Overview
--------------

    Probe:
     -P, --probe
       Probe network for devices.

    Wake:
     -W, --wake <user-credential>
       Wake device using specified user credential.

    Options:
     -B, --broadcast
       Send broadcasts.

     -L, --local-port <port address>
       Specifiy a local port address.

     -H, --remote-host <host address>
       Specifiy a remote host address.

     -R, --remote-port <port address>
       Specifiy a remote port address (default: 987).

     -I, --interface <interface>
       Bind to interface.

     -j, --json
       Output JSON.

     -v, --verbose
       Enable verbose messages.


Examples
--------

To search your whole network for a PS5:

    # ./ps5-wake -vP -B

To search via broadcasts using a specific network interface, eth0 for example:

    # ./ps5-wake -vP -B -I eth0

To send a probe directly to the PS5 using its IPv4 address, 192.168.1.10 for example:

    # ./ps5-wake -vP -H 192.168.1.10

To wake-up your PS5 using 123456 as the "user credential":

    Via broadcast:
    # ./ps5-wake -vW 123456 -B

    Or, direct:
    # ./ps5-wake -vW 123456 -H 192.168.1.10

