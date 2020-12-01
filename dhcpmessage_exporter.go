package main

import (
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "github.com/google/gopacket/layers"
   "log"
   "time"
   "github.com/prometheus/client_golang/prometheus"
   "github.com/prometheus/client_golang/prometheus/promhttp"
   "net/http"
   "strings"
   "flag"
)

var (
   snapshot_len int32  = 1500
   err          error
   timeout      time.Duration = 100 * time.Millisecond
   handle       *pcap.Handle
)

var (

  // METRIKE ZA PROMETHEUS
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
      Help: "The total number of captured packets",
    },
    []string{"type"},
  )


  // OBNASANJE GLEDE NA CLI ARGUMENTE
  listenAddr  = flag.String("listen-address", ":8067", "The address to listen for HTTP requests.")
  interfaces  = flag.String("interfaces", "eth0", "One or many interfaces to listen for DHCP packets. Use whitespace for separator.")
  promiscuous =   flag.Bool("promisc", false, "Set to true if you need interface in promiscuous mode.")
  filter      = flag.String("filter", "udp and port 67", "Change if needed :)")
  debug       =   flag.Bool("debug", false, "Print filtered packets to stdout")
)

func main() {

  // PARSE COMMAND LINE ARGUMENTS
  flag.Parse()
  log.Printf("filter=%s", *filter)
  log.Printf("listen-address=%s", *listenAddr)
  log.Printf("interfaces=%s", *interfaces)
  log.Printf("promisc=%t", *promiscuous)
  log.Printf("debug=%t", *debug)

  ifaces:= strings.Fields(*interfaces)
  for _, iface := range ifaces {
    // INICIALIZACIJA SNIFFERJA ZA VSAK DEVICE POSEBEJ
    go capture(iface)
  }

  // ZACETNE VREDNOSTI METRIK
  dhcpMsgs.With(prometheus.Labels{"type":"discover"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"offer"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"request"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"ack"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"nak"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"release"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"decline"}).Add(0)
  dhcpMsgs.With(prometheus.Labels{"type":"inform"}).Add(0)
  packetCounter.With(prometheus.Labels{"type":"all"}).Add(0)

  // HTTP ENDPOINT /metrics ZA PROMETHEUS JOB
  prometheus.MustRegister(dhcpMsgs)
  prometheus.MustRegister(packetCounter)
  http.Handle("/metrics", promhttp.Handler())
  log.Printf("HTTP endpoint /metrics ready on %s\n", *listenAddr)
  log.Fatal(http.ListenAndServe(*listenAddr, nil))

}

func capture(iface string) {
   // HANDLE ZA PCAP NA INTERFACEU
   handle, err = pcap.OpenLive(iface, snapshot_len, *promiscuous, timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // FILTER ZA SNIFANJE
   //var filter string = "udp and port 67"
   err = handle.SetBPFFilter(*filter)
   if err != nil {
      log.Fatal(err)
   }
   log.Printf("Capturing on %s: %s\n", iface, *filter)

   // PARSER PAKETOV
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {

      if *debug {
         log.Println(packet)
      }

      // COUNTER VSEH PAKETOV
      packetCounter.With(prometheus.Labels{"type":"all"}).Inc()

      // NAD INCOMING PAKETOM APPLYAS LayerTypeDHCPv4
      dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4)

      // CE JE V UDP PAKETU PRISOTEN DHCPv4 LAYER GREMO PARSAT DALJE - DHCP OPTIONS
      if dhcpv4 != nil {
         dhcp, _ := dhcpv4.(*layers.DHCPv4)
         opts := dhcp.Options

         // LOOP CEZ VSE DHCP OPTIONE V PAKETU
         for _, o := range opts {

            // CE JE KATERI OD OPTIONOV TIPA DHCPOptMessageType
            if o.Type == layers.DHCPOptMessageType && len(o.Data) == 1 {
              //log.Printf("packet on %s\n", iface)

              // POVECAJ USTREZEN COUNTER GLEDE NA DHCPMsgType
              switch layers.DHCPMsgType(o.Data[0]) {

                case layers.DHCPMsgTypeDiscover:
                  dhcpMsgs.With(prometheus.Labels{"type":"discover"}).Inc()

                case layers.DHCPMsgTypeOffer:
                  dhcpMsgs.With(prometheus.Labels{"type":"offer"}).Inc()

                case layers.DHCPMsgTypeRequest:
                  dhcpMsgs.With(prometheus.Labels{"type":"request"}).Inc()

                case layers.DHCPMsgTypeAck:
                  dhcpMsgs.With(prometheus.Labels{"type":"ack"}).Inc()

                case layers.DHCPMsgTypeNak:
                  dhcpMsgs.With(prometheus.Labels{"type":"nak"}).Inc()

                case layers.DHCPMsgTypeRelease:
                  dhcpMsgs.With(prometheus.Labels{"type":"release"}).Inc()

                case layers.DHCPMsgTypeDecline:
                  dhcpMsgs.With(prometheus.Labels{"type":"decline"}).Inc()

                case layers.DHCPMsgTypeInform:
                  dhcpMsgs.With(prometheus.Labels{"type":"inform"}).Inc()

               }
            }
         }
      }
   }
}
