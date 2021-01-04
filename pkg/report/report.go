package report

import( 
	"fmt"
	"sort"
	"time"
	"strconv"
	"github.com/pwdz/WirePenguin/pkg/filehandler"
)


type pair struct {
	Key   string
	Value int
}

type pairList []pair
func (p pairList) Len() int           { return len(p) }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p pairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

func Report(maxPacketSize, minPacketSize uint16, totalPacketsLength uint64, totalPacketsCount int, ipFragments map[uint16]int, ipPacket map[string]int, icmpCount, tcpCount, udpCount int){
	fmt.Println("##############################################################")
	fmt.Println("##############################################################")
	fmt.Println("##############################################################")
	fmt.Println("##############################################################")
	fmt.Println("max length:",maxPacketSize)
	fmt.Println("min length:",minPacketSize)
	fmt.Println("total length:",totalPacketsLength)
	fmt.Println("total count:", totalPacketsCount)
	fmt.Println("total icmp:",icmpCount)
	fmt.Println("total tcp:", tcpCount)
	fmt.Println("total udp:", udpCount)

	totalFragmentations := len(ipFragments)
	fmt.Println("total fragmentations:", totalFragmentations)

	t := time.Now().Unix()
	
	filehandler.SaveCountRecords("./reports/"+strconv.FormatInt(t, 10)+"-Counts.txt", minPacketSize, maxPacketSize, totalPacketsLength, totalPacketsCount, icmpCount, tcpCount, udpCount, totalFragmentations)
	filehandler.SaveIPPacketRecords("./reports/"+strconv.FormatInt(t, 10)+"-IpPacketsSorted.txt", ipPacket)
	p := make(pairList, len(ipPacket))

	i := 0
	for k, v := range ipPacket {
		p[i] = pair{k, v}
		i++
	}

	
	sort.Sort(p)
	//p is sorted
	
	for _, k := range p {
        fmt.Printf("%v\t%v\n", k.Key, k.Value)
    }

}