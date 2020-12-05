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
	"runtime/debug"
        "encoding/hex"
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
		[]string{"type", "interface"},
	)

	packetCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_captured_total",
			Help: "The total number of packets that passed bpf filter",
		},
		[]string{"type", "interface"},
	)

	// CLI ARGUMENTS
	listenAddr  = flag.String("listen-address", ":8067", "The address to listen for HTTP requests.")
	interfaces  = flag.String("interfaces", "eth0", "One or many interfaces to listen for DHCP packets. Use whitespace for separator.")
	promiscuous = flag.Bool("promisc", false, "Set to true if you need interface in promiscuous mode.")
	filter      = flag.String("filter", "udp and port 67", "Change if needed :)")
	bDebug      = flag.Bool("debug", false, "Print filtered packets to stdout")
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
	log.Printf("debug=%t", *bDebug)

	// GOROUTINE PER DEVICE
	ifaces := strings.Fields(*interfaces)
	for _, iface := range ifaces {

		// INITIALIZE VALUES
		packetCounter.With(prometheus.Labels{"type": "all", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "discover", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "offer", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "request", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "ack", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "nak", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "release", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "decline", "interface": iface}).Add(0)
		dhcpMsgs.With(prometheus.Labels{"type": "inform", "interface": iface}).Add(0)

		go capture(iface)
	}


	// HTTP ENDPOINT /metrics FOR PROMETHEUS
	prometheus.MustRegister(dhcpMsgs)
	prometheus.MustRegister(packetCounter)
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("HTTP endpoint /metrics ready on %s\n", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))

}

func capture(iface string) {

	defer func() {
		if r := recover(); r != nil {
			log.Println("stacktrace from panic: \n" + string(debug.Stack()))
		}
	}()

        // OPEN INTERFACE
	handle, err = pcap.OpenLive(iface, snapshot_len, *promiscuous, timeout)
	if err != nil {
		log.Fatal("pcap.OpenLive() ERROR:",err)
	}
	defer handle.Close()

	// SET BPF FILTER
	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Fatal("handle.SetBPFFilter() ERROR:",err)
	}

	log.Printf("Capturing on %s: %s\n", iface, *filter)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dhcpv4)
	decoded := []gopacket.LayerType{}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

        //for packet, err := packetSource.NextPacket() {
	for {
		// FETCH PACKET
		packet, err := packetSource.NextPacket()

		// CATCH READ ERRORS
		if err != nil {
			log.Println("packetSource.NextPacket() ERROR:",err)
                        fmt.Println(hex.Dump(packet.Data()))
                        fmt.Printf("%#v\n", packet.Data())
                        fmt.Println("Error reading in packet END")
			continue
                }

		// CATCH PACKET DECODER ERRORS
                if packet.ErrorLayer() != nil {
			log.Println("packetSource.ErrorLayer() ERROR:",err)
                        fmt.Println("\n\n\nError decoding packet:", packet.ErrorLayer().Error())
                        fmt.Println(hex.Dump(packet.Data()))
                        fmt.Printf("%#v\n", packet.Data())
                        for _, l := range packet.Layers() {
                                fmt.Printf("--- LAYER %v ---\n%#v\n\n", l.LayerType(), l)
                        }
			continue
                }

		if *bDebug {
			log.Println(packet)
		}

		// COUNT PACKETS THAT PASS BPF FILTER
		packetCounter.With(prometheus.Labels{"type": "all", "interface": iface}).Inc()

		// RUN DECODER
		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			log.Println("parser.DecodeLayer() ERROR:",err)
			continue
		}

		// FOR EACH DECODED LAYER
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
							dhcpMsgs.With(prometheus.Labels{"type": "discover", "interface": iface}).Inc()

						case layers.DHCPMsgTypeOffer:
							dhcpMsgs.With(prometheus.Labels{"type": "offer", "interface": iface}).Inc()

						case layers.DHCPMsgTypeRequest:
							dhcpMsgs.With(prometheus.Labels{"type": "request", "interface": iface}).Inc()

						case layers.DHCPMsgTypeAck:
							dhcpMsgs.With(prometheus.Labels{"type": "ack", "interface": iface}).Inc()

						case layers.DHCPMsgTypeNak:
							dhcpMsgs.With(prometheus.Labels{"type": "nak", "interface": iface}).Inc()

						case layers.DHCPMsgTypeRelease:
							dhcpMsgs.With(prometheus.Labels{"type": "release", "interface": iface}).Inc()

						case layers.DHCPMsgTypeDecline:
							dhcpMsgs.With(prometheus.Labels{"type": "decline", "interface": iface}).Inc()

						case layers.DHCPMsgTypeInform:
							dhcpMsgs.With(prometheus.Labels{"type": "inform", "interface": iface}).Inc()

						}
					}
				}
			}
		}
	}
}
