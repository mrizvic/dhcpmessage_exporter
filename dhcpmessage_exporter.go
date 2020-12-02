package main

import (
	"os"
	"fmt"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	// BUILD WITH -ldflags "-X main.GitCommit=$GIT_COMMIT"
	GitCommit    string = "development"
	snapshot_len int32 = 1500
	err          error
	timeout      time.Duration = -100 * time.Millisecond
	handle       *pcap.Handle

	// PACKET CONTAINERS
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP
	dhcpv4 layers.DHCPv4


	// PROMETHEUS METRICS
	dhcpMsgs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dhcp_messages_processed_total",
			Help: "The total number of processed DHCP messagess",
		},
		[]string{"type"},
	)

	packetCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_captured_total",
			Help: "The total number of packets that passed bpf filter",
		},
		[]string{"type"},
	)

	// CLI ARGUMENTS
	listenAddr  = flag.String("listen-address", ":8067", "The address to listen for HTTP requests.")
	interfaces  = flag.String("interfaces", "eth0", "One or many interfaces to listen for DHCP packets. Use whitespace for separator.")
	promiscuous = flag.Bool("promisc", false, "Set to true if you need interface in promiscuous mode.")
	filter      = flag.String("filter", "udp and port 67", "Change if needed :)")
	debug       = flag.Bool("debug", false, "Print filtered packets to stdout")
	bVersion    = flag.Bool("version", false, "Show version")
)

func main() {

	// CLI ARGUMENTS
	flag.Parse()

	if (*bVersion) {
		fmt.Println(GitCommit)
		os.Exit(0)
	}

	log.Printf("version=%s", GitCommit)
	log.Printf("filter=%s", *filter)
	log.Printf("listen-address=%s", *listenAddr)
	log.Printf("interfaces=%s", *interfaces)
	log.Printf("promisc=%t", *promiscuous)
	log.Printf("debug=%t", *debug)

	ifaces := strings.Fields(*interfaces)
	for _, iface := range ifaces {
		// GO CAPTURE PER DEVICE
		go capture(iface)
	}

	// INITIALIZE VALUES
	dhcpMsgs.With(prometheus.Labels{"type": "discover"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "offer"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "request"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "ack"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "nak"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "release"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "decline"}).Add(0)
	dhcpMsgs.With(prometheus.Labels{"type": "inform"}).Add(0)
	packetCounter.With(prometheus.Labels{"type": "all"}).Add(0)

	// HTTP ENDPOINT /metrics FOR PROMETHEUS
	prometheus.MustRegister(dhcpMsgs)
	prometheus.MustRegister(packetCounter)
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("HTTP endpoint /metrics ready on %s\n", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))

}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func capture(iface string) {

        // OPEN INTERFACE
	handle, err = pcap.OpenLive(iface, snapshot_len, *promiscuous, timeout)
	checkError(err)
	defer handle.Close()

	// SET BPF FILTER
	err = handle.SetBPFFilter(*filter)
	checkError(err)
	log.Printf("Capturing on %s: %s\n", iface, *filter)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dhcpv4)
	decoded := []gopacket.LayerType{}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		// FETCH PACKET
		packet, err := packetSource.NextPacket()
		checkError(err)

		if *debug {
			log.Println(packet)
		}

		// COUNT PACKETS THAT PASS BPF FILTER
		packetCounter.With(prometheus.Labels{"type": "all"}).Inc()

		// RUN DECODER
		err = parser.DecodeLayers(packet.Data(), &decoded)
		checkError(err)

		for _, layerType := range decoded {

			switch layerType {
			case layers.LayerTypeDHCPv4:

				// LOOP OVER ALL DHCP OPTIONS
				for _, o := range dhcpv4.Options {

					// ONLY PARSE OPTION 53 - DHCPOptMessageType
					if o.Type == layers.DHCPOptMessageType && len(o.Data) == 1 {

						// INCREASE RESPECTIVE COUNTER - DHCPMsgType
						switch layers.DHCPMsgType(o.Data[0]) {

						case layers.DHCPMsgTypeDiscover:
							dhcpMsgs.With(prometheus.Labels{"type": "discover"}).Inc()

						case layers.DHCPMsgTypeOffer:
							dhcpMsgs.With(prometheus.Labels{"type": "offer"}).Inc()

						case layers.DHCPMsgTypeRequest:
							dhcpMsgs.With(prometheus.Labels{"type": "request"}).Inc()

						case layers.DHCPMsgTypeAck:
							dhcpMsgs.With(prometheus.Labels{"type": "ack"}).Inc()

						case layers.DHCPMsgTypeNak:
							dhcpMsgs.With(prometheus.Labels{"type": "nak"}).Inc()

						case layers.DHCPMsgTypeRelease:
							dhcpMsgs.With(prometheus.Labels{"type": "release"}).Inc()

						case layers.DHCPMsgTypeDecline:
							dhcpMsgs.With(prometheus.Labels{"type": "decline"}).Inc()

						case layers.DHCPMsgTypeInform:
							dhcpMsgs.With(prometheus.Labels{"type": "inform"}).Inc()

						}
					}
				}
			}
		}
	}
}
