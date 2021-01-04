package list

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)
func ListDevices() {
	// var devices pcap.
	devices, err := pcap.FindAllDevs()
	if err != nil{
		log.Fatal(err)
	}

	fmt.Println("Interfaces:")
	for _, dev := range devices{
		fmt.Println("Name:", dev.Name)
		fmt.Println("Description:", dev.Description)
		fmt.Println("Address:", dev.Addresses)
		// fmt.Println("Flags:", dev.Flags)
		fmt.Println("================================================")
	}

}