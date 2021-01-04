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

	"github.com/pwdz/WirePenguin/pkg/sniffer"
	"github.com/spf13/cobra"
)

// openCmd represents the open command
var openCmd = &cobra.Command{
	Use:   "open",
	Short: "TODO",
	Long: `TODO`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

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
		
		sniffer.OpenOffline(path, num, report, 
		tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket)
	},
}

func init() {
	RootCmd.AddCommand(openCmd)

	openCmd.Flags().StringP("filter", "f", "", "wanted layers, for exp: TCP, UDP, ...")
	openCmd.Flags().BoolP("report", "r", false, "want report")

	openCmd.Flags().IntP("num","n",-1,"Maximum number of packets to capture")
}
