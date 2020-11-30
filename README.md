# TODO
Pogruntaj kakšen `setcap` flag potrebuje binary, da bo lahko preko pcap poslušal za promet in mu ne bo treba laufati kot root (systemd unit):
```
User=root
Group=root
```

# DONE
Uporabi `setcap` da procesa ni potrebno poganjati kot root:
```
setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/dhcpmessage_exporter-linux-amd64
```

# Kaj je to
Zadeva posluša (pcap) na različnih mrežnih vmesnikih za dhcp promet (bpf filter: udp and port 67) ter prepozna in sešteva naslednja dhcp sporočila:
- discover
- offer
- request
- ack
- nak
- inform
- release

Statistika je na voljo preko HTTP v obliki, ki je primerna za prometheus:

```
dhcp-lab$ curl -s localhost:8067/metrics |grep dhcp
# HELP dhcp_messages_processed_total The total number of processed DHCP messagess
# TYPE dhcp_messages_processed_total counter
dhcp_messages_processed_total{type="ack"} 13
dhcp_messages_processed_total{type="decline"} 0
dhcp_messages_processed_total{type="discover"} 61
dhcp_messages_processed_total{type="inform"} 0
dhcp_messages_processed_total{type="nak"} 0
dhcp_messages_processed_total{type="offer"} 3
dhcp_messages_processed_total{type="release"} 57
dhcp_messages_processed_total{type="request"} 70
```

# Zakaj bi to rabl?

Zato :)

![grafana](https://github.com/mrizvic/dhcpmessage_exporter/blob/main/grafana-dhcpmessage_exporter.png)


# CLI argumenti pri zagonu
```
Usage of ./dhcpmessage_exporter:
  -debug
        Print all packets to stdout
  -filter string
        Change if needed :) (default "udp and port 67")
  -interfaces string
        One or many interfaces to listen for DHCP packets. Use whitespace for separator. (default "eth0")
  -listen-address string
        The address to listen for HTTP requests. (default ":8067")
  -promisc
        Set to true if you need interface in promiscuous mode.
```
Kadar dhcp servira na različnih vmesnikih tedaj naredis seznam in ga podaš kot en string:
```
dhcpmessage_exporter -interfaces="bond0.25 bond0.57 bond0.74"
```

Če je samo na enem vmesniku pa brez narekovajev:
```
dhcpmessage_exporter -interfaces=eth1
```


# build

Ukaz za prevajanje izvorne kode v static binary, ki testirano laufa na CentOS8 kakor tudi CentOS6:
```
make deps
make bin
```

# deploy

Binary file skopiraš na dhcp strežnik kjer potrebuješ statistiko.
Preden narediš systemd unit si pripravi seznam interfaceov na katerih je dhcp servis aktiven.

Na strežniku narediš systemd unit:

```
cat > /etc/systemd/system/dhcpmessage_exporter.service<<EOF
[Unit]                             
Description=dhcp message sniffer and counter for prometheus
Documentation=https://github.com/mrizvic/dhcpmessage_exporter
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecReload=/bin/kill -HUP 
ExecStart=/usr/local/bin/dhcpmessage_exporter-linux-amd64 -promiscuous=false -interfaces="ens192 ens193 ens224 ens256" -listen-address=":8067"

SyslogIdentifier=dhcpmessage
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```
Ne pozabi na reload systemd, da bo prepoznal nov unit. Potem pa start servisa in enable ob bootu.

```
sudo systemctl daemon-reload
sudo systemctl start dhcpmessage_exporter.service
sudo systemctl enable dhcpmessage_exporter.service
```

Preveri status:
```
sudo systemctl status dhcpmessage_exporter.service
● dhcpmessage_exporter.service - dhcp message sniffer and counter for prometheus
   Loaded: loaded (/etc/systemd/system/dhcpmessage_exporter.service; disabled; vendor preset: disabled)
   Active: active (running) since Mon 2020-11-30 08:19:38 CET; 14min ago
     Docs: https://github.com/mrizvic/dhcpmessage_exporter
 Main PID: 16948 (dhcpmessage_exp)
    Tasks: 13 (limit: 23583)
   Memory: 16.6M
   CGroup: /system.slice/dhcpmessage_exporter.service
           └─16948 /usr/local/bidhcpmessage_exporter-linux-amd64 -interfaces ens192 ens193 ens224 ens256 -listen-address :8067

Nov 30 08:19:38 dhcp-lab systemd[1]: Started dhcp message sniffer and counter for prometheus.
Nov 30 08:19:38 dhcp-lab dhcpmessage[16948]: 2020/11/30 08:19:38 Beginning to serve on :8067
Nov 30 08:19:38 dhcp-lab dhcpmessage[16948]: 2020/11/30 08:19:38 BPF FILTER ON INTERFACE ens224: udp and port 67
Nov 30 08:19:38 dhcp-lab dhcpmessage[16948]: 2020/11/30 08:19:38 BPF FILTER ON INTERFACE ens192: udp and port 67
Nov 30 08:19:38 dhcp-lab dhcpmessage[16948]: 2020/11/30 08:19:38 BPF FILTER ON INTERFACE ens256: udp and port 67
Nov 30 08:19:38 dhcp-lab dhcpmessage[16948]: 2020/11/30 08:19:38 BPF FILTER ON INTERFACE ens193: udp and port 67
```

