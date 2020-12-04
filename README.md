# What is this
It listens (pcap) on specific network interfaces for dhcp traffic (bpf filter: udp and port 67) and counts following DHCP messages:
- discover
- offer
- request
- ack
- nak
- inform
- release
- decline

Stats are available over HTTP in format suitable for prometheus:

```
dhcp-lab$ curl -s localhost:8067/metrics |grep dhcp
# HELP dhcp_messages_processed_total The total number of processed DHCP messagess
# TYPE dhcp_messages_processed_total counter
dhcp_messages_processed_total{interface="ens192",type="ack"} 0
dhcp_messages_processed_total{interface="ens192",type="decline"} 0
dhcp_messages_processed_total{interface="ens192",type="discover"} 0
dhcp_messages_processed_total{interface="ens192",type="inform"} 0
dhcp_messages_processed_total{interface="ens192",type="nak"} 0
dhcp_messages_processed_total{interface="ens192",type="offer"} 0
dhcp_messages_processed_total{interface="ens192",type="release"} 0
dhcp_messages_processed_total{interface="ens192",type="request"} 0
dhcp_messages_processed_total{interface="ens193",type="ack"} 2
dhcp_messages_processed_total{interface="ens193",type="decline"} 0
dhcp_messages_processed_total{interface="ens193",type="discover"} 12
dhcp_messages_processed_total{interface="ens193",type="inform"} 0
dhcp_messages_processed_total{interface="ens193",type="nak"} 0
dhcp_messages_processed_total{interface="ens193",type="offer"} 0
dhcp_messages_processed_total{interface="ens193",type="release"} 12
dhcp_messages_processed_total{interface="ens193",type="request"} 14
dhcp_messages_processed_total{interface="ens224",type="ack"} 1
dhcp_messages_processed_total{interface="ens224",type="decline"} 0
dhcp_messages_processed_total{interface="ens224",type="discover"} 0
dhcp_messages_processed_total{interface="ens224",type="inform"} 0
dhcp_messages_processed_total{interface="ens224",type="nak"} 0
dhcp_messages_processed_total{interface="ens224",type="offer"} 0
dhcp_messages_processed_total{interface="ens224",type="release"} 0
dhcp_messages_processed_total{interface="ens224",type="request"} 1
dhcp_messages_processed_total{interface="ens256",type="ack"} 14
dhcp_messages_processed_total{interface="ens256",type="decline"} 0
dhcp_messages_processed_total{interface="ens256",type="discover"} 3
dhcp_messages_processed_total{interface="ens256",type="inform"} 0
dhcp_messages_processed_total{interface="ens256",type="nak"} 0
dhcp_messages_processed_total{interface="ens256",type="offer"} 9
dhcp_messages_processed_total{interface="ens256",type="release"} 0
dhcp_messages_processed_total{interface="ens256",type="request"} 4
# HELP packets_captured_total The total number of packets that passed bpf filter
# TYPE packets_captured_total counter
packets_captured_total{interface="ens192",type="all"} 0
packets_captured_total{interface="ens193",type="all"} 40
packets_captured_total{interface="ens224",type="all"} 2
packets_captured_total{interface="ens256",type="all"} 30
```

# Grafana dashboard

![grafana](https://github.com/mrizvic/dhcpmessage_exporter/blob/main/grafana-dhcpmessage_exporter.png)


# Command line interface

```
Usage of dhcpmessage_exporter-linux-amd64:
  -debug
        Print filtered packets to stdout
  -filter string
        Change if needed :) (default "udp and port 67")
  -interfaces string
        One or many interfaces to listen for DHCP packets. Use whitespace for separator. (default "eth0")
  -listen-address string
        The address to listen for HTTP requests. (default ":8067")
  -promisc
        Set to true if you need interface in promiscuous mode.
  -version
        Show version
```
If more than one interface is used it must be specified as string:
```
dhcpmessage_exporter-linux-amd64 -interfaces="bond0.25 bond0.57 bond0.74"
```

Single interface can be specified without quotes
```
dhcpmessage_exporter -interfaces=eth1
```


# build

Installation of golang and make is not subject of this writing.

```
make deps
make bin
```

# deploy

Put a binary file somewhere in system path to your liking. Im using `/usr/local/bin/`

Use `setcap` so the process can pcap.OpenLive(iface) without need to run as root user:
```
setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/dhcpmessage_exporter-linux-amd64
```

Create  systemd unit:

```
cat > /etc/systemd/system/dhcpmessage_exporter.service<<EOF
[Unit]                             
Description=capture dhcp messages, count by message type and export for prometheus
Documentation=https://github.com/mrizvic/dhcpmessage_exporter
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=nobody
Group=nobody
ExecReload=/bin/kill -HUP 
ExecStart=/usr/local/bin/dhcpmessage_exporter-linux-amd64 -promiscuous=false -interfaces="ens192 ens193 ens224 ens256" -listen-address=":8067"

SyslogIdentifier=dhcpmessage
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```
Dont forget to reload systemd. Then start and enable this service.

```
sudo systemctl daemon-reload
sudo systemctl start dhcpmessage_exporter.service
sudo systemctl enable dhcpmessage_exporter.service
```

Check status:
```
sudo systemctl status dhcpmessage_exporter.service
● dhcpmessage_exporter.service -capture dhcp messages, count by message type and export for prometheus
   Loaded: loaded (/etc/systemd/system/dhcpmessage_exporter.service; disabled; vendor preset: disabled)
   Active: active (running) since Mon 2020-11-30 08:19:38 CET; 14min ago
     Docs: https://github.com/mrizvic/dhcpmessage_exporter
 Main PID: 16948 (dhcpmessage_exp)
    Tasks: 13 (limit: 23583)
   Memory: 16.6M
   CGroup: /system.slice/dhcpmessage_exporter.service
           └─16948 /usr/local/bidhcpmessage_exporter-linux-amd64 -interfaces ens192 ens193 ens224 ens256 -listen-address :8067

Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 filter=udp and port 67
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 listen-address=:8067
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 interfaces=ens192 ens193 ens224 ens256
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 promisc=false
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 debug=false
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 HTTP endpoint /metrics ready on :8067
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 Capturing on ens224: udp and port 67
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 Capturing on ens192: udp and port 67
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 Capturing on ens256: udp and port 67
Dec 04 17:21:10 dhcp-lab dhcpmessage[11035]: 2020/12/04 17:21:10 Capturing on ens193: udp and port 67
```

