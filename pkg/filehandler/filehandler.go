package filehandler

import (
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)


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