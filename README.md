# Packet Generator

This program is packet generator and reciever.
The generator can set the MAC, IP, and UDP header of the packet freely, and the receiver can receive all packets on network (promiscuous mode).
To receive all packets, the program require root privilege.

## Build

You can buld this program by using gcc.

``` bash
gcc generator.c
```

## Use

This program require root privilege.

``` bash
# Receive all packets
sudo ./a.out r

# Receive target packets
sudo ./a.out R

# Send permutation value packets
sudo ./a.out s

# Send randomized value packets
sudo ./a.out S
```
