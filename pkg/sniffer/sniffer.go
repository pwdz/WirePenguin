package sniffer

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	// "github.com/pwdz/WirePenguin/utils/filehandler"
	"github.com/pwdz/WirePenguin/pkg/filehandler"
)
const(
	snapshotLen int32 = 65535
	promiscuous bool = false
	timeout time.Duration = -1 * time.Second
)
var (
	err error
	handle *pcap.Handle

	tcpCount, udpCount, icmpCount, ipv4Count, ipv6count, dnsCount, armCount int
	ipPacket map[string]int
	fragmentCount int
	minPacketSize, maxPacketSize, averageSize int

	writer *pcapgo.Writer
	pcapFile *os.File
)
func RunConsole(){
	fmt.Println("[$] Starting Console...")
	// input := ""
	reader := bufio.NewReader(os.Stdin)
	for true{
		input,_ := reader.ReadString('\n')

		cmdStr := strings.Split(input, " ")[0]
		cmdStr = strings.Trim(cmdStr, "\n\r ")

		if cmdStr == "exit"{

		}
	}
}
func clearCounters(){
	udpCount = 0
	tcpCount = 0
	icmpCount = 0
	fragmentCount = 0
	dnsCount = 0
	armCount = 0
	ipv4Count = 0
	ipv6count = 0
	minPacketSize = 10000000
	maxPacketSize = -1
	ipPacket = make(map[string]int)
}
func OpenOffline(filePath string, maxPacket int, report bool, tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket bool) error{
	handle, err := pcap.OpenOffline(filePath)
	if err != nil{
		log.Fatal(err)
		return err
	}
	defer handle.Close()

	return ReadPackets(handle, maxPacket,"",tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket)
}
func CaptureLive(deviceName, pcapPath string, maxPacket int, report bool,tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket bool) error{

	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil{
		log.Fatal(err)
		return err
	}
	defer handle.Close()

	return ReadPackets(handle, maxPacket, pcapPath,tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket)
}
func ReadPackets(handle *pcap.Handle, maxPacket int, pcapOut string ,tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket bool) error{
	clearCounters();
	if pcapOut != ""{
		writer, pcapFile, _ = filehandler.InitFile(pcapOut)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets(){
		// fmt.Println("=========================================================================")
		fmt.Println("=================================PACKET==================================")
		// fmt.Println("=========================================================================")
		if layers{
			printLayers(packet)
		}
		if tcp{
			checkTCP(packet)
		}
		if udp{
			checkUDP(packet)
		}
		if ipv4{
			checkIPv4(packet)
		}
		if ipv6{
			checkIPv6(packet)
		}
		if icmp{
			checkICMP(packet)
		}
		if showPacket{
			printPacket(packet)
		}
		
		if pcapOut != "" {
			filehandler.SavePacket(writer, packet)
		}
		if maxPacket > 0 {
			maxPacket--;
			if maxPacket == 0{
				break
			}
		}
		
	}

	defer pcapFile.Close()
	return nil
}
func checkIPv4(packet gopacket.Packet){
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil{
		ip, _ := ip4Layer.(*layers.IPv4)

		ipv4Count++;

		if value, ok := ipPacket[ip.SrcIP.String()]; !ok{
			ipPacket[ip.SrcIP.String()] = 1
		}else{
			ipPacket[ip.SrcIP.String()] = value + 1
		}

		
		fmt.Println("Type:", ip.LayerType())
		fmt.Printf("From %s, To %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol:",ip.Protocol)
		fmt.Println("Flags:", ip.Flags)
		fmt.Println("FragOffset:", ip.FragOffset)
		fmt.Println("IHL:", ip.IHL)
		fmt.Println("Id:", ip.Id)
		fmt.Println("Length:", ip.Length)
		fmt.Println("Options:", ip.Options)

		fmt.Println("Padding:", ip.Padding)
		fmt.Println("BaseLayer:", ip.BaseLayer)
		fmt.Println("Checksum:", ip.Checksum)
		fmt.Println("TTL:", ip.TTL)
		fmt.Println("version:", ip.Version)
		fmt.Println("TOS:", ip.TOS)

		fmt.Println("##########################IPv4###############################")
	}
}
func checkIPv6(packet gopacket.Packet){
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil{
		ip6, _ := ip6Layer.(*layers.IPv6)
		
		fmt.Println("Type:", ip6.LayerType())
		fmt.Printf("From: %s, To: %s\n", ip6.SrcIP, ip6.DstIP)
		fmt.Println("HopByHop",ip6.HopByHop)
		fmt.Println("HopLimit",ip6.HopLimit)
		fmt.Println("FlowLabel",ip6.FlowLabel)
		fmt.Println("TrafficClass",ip6.TrafficClass)

		fmt.Println("Length:", ip6.Length)
		fmt.Println("Content:", ip6.Contents)
		fmt.Println("Payload",ip6.Payload)

		fmt.Println("NextHeader",ip6.NextHeader)
		fmt.Println("##########################IPv6###############################")
	}
}
func checkTCP(packet gopacket.Packet){
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp,_ := tcpLayer.(*layers.TCP)
		tcpCount++;

		fmt.Println("Type:", tcp.LayerType())

		fmt.Printf("From port: %s, To port: %s\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Options:", tcp.Options)
		fmt.Println("Padding:", tcp.Padding)
		fmt.Println("Urgent:", tcp.Urgent)
		fmt.Println("Window:", tcp.Window)
		fmt.Println("Seq:", tcp.Seq)
		fmt.Println("int Ack :", tcp.Ack)
		fmt.Println("Bool ACK:", tcp.ACK)
		fmt.Println("Bool CWR:", tcp.CWR)
		fmt.Println("Bool URG:", tcp.URG)
		fmt.Println("Bool ECE:", tcp.ECE)
		fmt.Println("Bool FIN:", tcp.FIN)
		fmt.Println("Bool NS:", tcp.NS)
		fmt.Println("Bool RST:", tcp.RST)
		fmt.Println("Bool PSH:", tcp.PSH)
		fmt.Println("Bool Syn:", tcp.SYN)
		fmt.Println("Offset:", tcp.DataOffset)

		fmt.Println("Content:", tcp.Contents)
		fmt.Println("Checksum:", tcp.Checksum)
		fmt.Println("BaseLayer:", tcp.BaseLayer)
		
		fmt.Println("##########################TCP###############################")
	
	}
}
func checkUDP(packet gopacket.Packet){
	udpLayer := packet.Layer(gopacket.LayerType(layers.LayerTypeUDP))
	if udpLayer != nil {
		udpCount++;

		udp,_ := udpLayer.(*layers.UDP)
		fmt.Println("Type:", udp.LayerType())
		fmt.Println("Length:", udp.Length)
		fmt.Println("SrcPort:", udp.SrcPort)
		fmt.Println("DstPort:", udp.DstPort)
		fmt.Println("Checksum:", udp.Checksum)
		fmt.Println("BaseLayer:", udp.BaseLayer)
		fmt.Println("Payload:", udp.Payload)
		fmt.Println("Contents:", udp.Contents)

		fmt.Println("##########################UDP###############################")
	}
	
}
func checkICMP(packet gopacket.Packet){
	icmpLayer := packet.Layer(gopacket.LayerType(layers.LayerTypeICMPv4))
	if icmpLayer != nil {
		icmp,_ := icmpLayer.(*layers.ICMPv4)
		icmpCount++;
		fmt.Println("Type:", icmp.LayerType())
		fmt.Println("TypeCode:", icmp.TypeCode)
		fmt.Println("Id:", icmp.Id)
		fmt.Println("Seq:", icmp.Seq)
		fmt.Println("BaseLayer:", icmp.BaseLayer)
		fmt.Println("Checksum:", icmp.Checksum)
		fmt.Println("Payload:", icmp.Payload)
		fmt.Println("##########################ICMP###############################")
	}
}
func checkTransportLayer(packet gopacket.Packet){
	if packet.TransportLayer() != nil{
		if packet.TransportLayer().LayerType() != layers.LayerTypeTCP{
			fmt.Println(packet.TransportLayer().LayerType())
		}
	} 
}
func printLayers(packet gopacket.Packet){

	fmt.Println("==================PACKET LAYERS===================")
	for _, layer := range packet.Layers(){
		fmt.Println(layer.LayerType())
	} 
}
func printPacket(packet gopacket.Packet){
	fmt.Println(packet)
}