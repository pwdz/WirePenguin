![Build](https://github.com/pwdz/WirePenguin/workflows/Build/badge.svg)
# WirePenguin
A CLI Packet Sniffer in golang using [Cobra](https://github.com/spf13/cobra) and [Gopacket](https://github.com/google/gopacket) packages much much simpler than WireShark =)  
You can capture packets both live or offline from .pcap files. Also can specify the wanted layers and etc.  

## Commands  

### list  
Lists all available network devices  
```
WirePenguin list
```  

### capture  
```
WirePenguin capture -i/--interface interfaceName -f/--filter filters
```  
`interfaceName` is one the network interfaces    
**Flags**  
***-o, --output***   
        Save captured packets in a `.pcap` file. Specify filePath/filname.pcap after flag.    
          
***-f, --filter***   
        Available filters: `tcp,udp,ipv4,ipv6,icmp,layers,showPacket`. use `all` if you don't want to filter any specified layer.  
          
***-r, --report  (optuinal)***   
        Save the results of packet capturing in files(2 files will be created. fileNames = "timestamps.Now" + "Counts.txt"/"IpPacketsSorted.txt")  
        There's info about the count of the `icmp, tcp, udp, minPacketSize, maxPacketSize, avgPacketSize, TotalFragmentations` in `Counts.txt` file.  
        Also in `IpPacketsSorted.txt`, sorted info about the count of the received packets per IP exists.   
          
***-n, --num (optional)***    
        Maximum number of packets you wanna capture.  
          
### open  
```
WirePenguin open filePath/filename.pcap -f/--filter filters
```  
**Flags**    
All flag perform the same action like the `capture` flags.
