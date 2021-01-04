// Copyright © 2021 pwdz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	// "fmt"
	"log"
	"strings"
	
	"github.com/pwdz/WirePenguin/pkg/sniffer"
	"github.com/spf13/cobra"
)

// captureCmd represents the capture command
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "TODO",
	Long: `TODO`,
	Run: func(cmd *cobra.Command, args []string) {
		
		device, err := cmd.Flags().GetString("interface")
		if err != nil{
			log.Fatal(err)
			return
		}
		
		pcapOutPath, err := cmd.Flags().GetString("output")
		if err != nil{
			log.Fatal(err)
			return
		}

		filter, err := cmd.Flags().GetString("filter")
		if err != nil{
			log.Fatal(err)
			return
		}
	
		num, err := cmd.Flags().GetInt("num")
		if err != nil{
			log.Fatal(err)
			return
		}
		
		report, err := cmd.Flags().GetBool("report")
		if err != nil{
			log.Fatal(err)
			return
		}
		var tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket bool
		parseFilters(filter, &tcp, &udp, &ipv4, &ipv6, &dns, &icmp, &layers, &showPacket)
		
		sniffer.CaptureLive(device, pcapOutPath, num, report, 
		tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket)
		// sniffer.RunConsole(task)
	},
}
func parseFilters(filter string, tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket *bool){
	filter = strings.ToLower(filter)
	if strings.Contains(filter, "tcp"){
		*tcp = true
	}
	if strings.Contains(filter, "udp"){
		*udp = true
	}
	if strings.Contains(filter, "ipv4"){
		*ipv4 = true
	}
	if strings.Contains(filter, "ipv6"){
		*ipv6 = true
	}
	if strings.Contains(filter, "dns"){
		*dns = true
	}
	if strings.Contains(filter, "icmp"){
		*icmp = true
	}
	if strings.Contains(filter, "layers"){
		*layers = true
	}
	if strings.Contains(filter, "packet"){
		*showPacket = true
	}
	if strings.Contains(filter, "all"){
		*tcp = true
		*udp = true
		*ipv4 = true
		*ipv6 = true
		*dns = true
		*icmp = true
		*layers = true
		*showPacket = true
	}
}

func init() {
	RootCmd.AddCommand(captureCmd)

	captureCmd.Flags().StringP("interface", "i", "", "Network interface")
	captureCmd.Flags().StringP("output", "o", "", "save capture results in path/file.pcap")
	captureCmd.Flags().StringP("filter", "f", "", "wanted layers, for exp: TCP, UDP, ...")
	captureCmd.Flags().BoolP("report", "r", false, "want report")

	captureCmd.Flags().IntP("num","n",-1,"Maximum number of packets to capture")
}
