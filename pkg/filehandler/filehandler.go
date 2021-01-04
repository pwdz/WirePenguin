package filehandler

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type pair struct {
	Key   string
	Value int
}

type pairList []pair
func (p pairList) Len() int           { return len(p) }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p pairList) Less(i, j int) bool { return p[i].Value > p[j].Value }


func InitFile(path string)(*pcapgo.Writer, *os.File , error){
	// os
	file, err := os.Create(path)
	if err!=nil{
		log.Fatal(err)
		return nil,nil, err
	}
	w := pcapgo.NewWriter(file)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	return w, file, nil

}
func SavePacket(writer *pcapgo.Writer, packet gopacket.Packet) error{
	writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	return nil
}
func SaveCountRecords(path string, maxPacketSize, minPacketSize uint16, totalPacketsLength uint64, totalPacketsCount,icmpCount, tcpCount, udpCount, totalFragmentations int ) error{
	file, err := os.Create(path)
	if err!=nil{
		log.Fatal(err)
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	writer.WriteString("max length:"+strconv.Itoa(int(maxPacketSize))+"\n")
	writer.WriteString("min length:"+strconv.Itoa(int(minPacketSize))+"\n")
	writer.WriteString("avg length:"+strconv.FormatUint( totalPacketsLength/uint64(totalPacketsCount) , 10)+"\n")

	writer.WriteString("total frags:"+strconv.Itoa(totalFragmentations)+"\n")
	writer.WriteString("total icmp:"+strconv.Itoa(icmpCount)+"\n")
	writer.WriteString("total tcp:"+strconv.Itoa(tcpCount)+"\n")
	writer.WriteString("total udp:"+strconv.Itoa(udpCount)+"\n")
	

	writer.Flush()
	return nil

}
func SaveIPPacketRecords(path string, ipPacket map[string]int)error{
	file, err := os.Create(path)
	if err!=nil{
		log.Fatal(err)
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	p := make(pairList, len(ipPacket))

	i := 0
	for k, v := range ipPacket {
		p[i] = pair{k, v}
		i++
	}

	
	sort.Sort(p)
	
	for _, k := range p {
		bytesWritten, err := writer.WriteString(k.Key+" \t"+strconv.Itoa(k.Value)+"\n")
		if err != nil {
            log.Fatalf("Got error while writing to a file. Err: %s", err.Error())
        }
        fmt.Printf("Bytes Written: %d\n", bytesWritten)
    }
	writer.Flush()
	// fmt.Println("kiriiiiiiiiiiiiiiiiiiii")
	return nil

}
