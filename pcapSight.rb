#!/usr/bin/env ruby
require 'packetfu'; require 'pcap_tools'; require 'rainbow'
# API dox http://planb-security.net/packetfu/doc/

# TO-DO:
# Get the src/dst ip parsing issues worked out
# Integrate into auto_snorter.rb
# See what else from a malware perspective makes sense to add as new features

  pcap         = ARGV[0] || exit # User supplies .pcap as an argument or app exits
  pcapd        = PacketFu::Read.f2a(:file => pcap) # alias for file_to_array
  total_count  = 0
  icmp_count   = 0
  tcp_count    = 0
	udp_count    = 0
  arp_count    = 0
	ftp_count    = 0
	http_count   = 0
  dns_count    = 0
	dhcp_count   = 0


  ### Process the supplied .pcap
  pcapd.each do |pkt|
  v = PacketFu::Packet.parse(pkt)

     # Begin packet count
     total_count += 1
     if v.is_icmp?
      icmp_count += 1
     elsif v.is_tcp?
      tcp_count += 1
     elsif v.is_udp?
      udp_count += 1
	   elsif v.is_arp?
      arp_count += 1
	   elsif v.is_ftp?
      ftp_count += 1
     elsif v.is_http?
      http_count += 1
	   elsif v.is_dns?
      dns_count += 1
	   else v.is_dhcp?
      dhcp_count += 1
		 end
	end

  # Read packets
  r = PacketFu::PcapFile.read(pcap)

  # Print main banner
  title = "[+] Packet attributes in '#{pcap}'".foreground(:white).bright
  puts "-" * title.size
  puts title
  puts "-" * title.size

  # Print total packet count
  puts "Total Packets: ".ljust(20).foreground(:magenta).bright + "#{total_count}".foreground(:magenta).bright

  # Print packet details
  puts "File Size: ".ljust(20).foreground(:magenta).bright + "#{r}".size.to_s.foreground(:magenta).bright + " bytes".foreground(:magenta).bright
  puts "TCP Packets: ".ljust(20).foreground(:magenta).bright + "#{tcp_count}".foreground(:magenta).bright
  puts "ICMP Packets: ".ljust(20).foreground(:magenta).bright + "#{icmp_count}".foreground(:magenta).bright
  puts "UDP Packets: ".ljust(20).foreground(:magenta).bright + "#{udp_count}".foreground(:magenta).bright
  puts "ARP Packets: ".ljust(20).foreground(:magenta).bright + "#{arp_count}".foreground(:magenta).bright
  puts "FTP Packets: ".ljust(20).foreground(:magenta).bright + "#{ftp_count}".foreground(:magenta).bright
  puts "HTTP Packets: ".ljust(20).foreground(:magenta).bright + "#{http_count}".foreground(:magenta).bright
  puts "DNS Packets: ".ljust(20).foreground(:magenta).bright + "#{dns_count}".foreground(:magenta).bright
  puts "DHCP Packets: ".ljust(20).foreground(:magenta).bright + "#{dhcp_count}\n".foreground(:magenta).bright



  ### Print TCP banner
  title = "[+] TCP Protocol Breakdown '#{pcap}'".foreground(:white).bright
  puts "-" * title.size
  puts title
  puts "-" * title.size

  # Print TCP details to user
  puts "Packets:".ljust(20).foreground(:magenta).bright + "#{tcp_count}".rjust(25).foreground(:magenta).bright
  
	# Read Source IP's
  #src = PacketFu::IPHeader.ip_saddr(pcap)
  #puts src
	puts "IP Src's:".ljust(20).foreground(:magenta).bright + "#{udp_count}".rjust(25).foreground(:magenta).bright

  # Read Destination IP's
  #dst = PacketFu::IPHeader.ip_daddr(pcap)
  #puts dst
	puts "IP Dst's:".ljust(20).foreground(:magenta).bright + "#{tcp_count}".rjust(25).foreground(:magenta).bright

	# Popular IP's
	puts "Popular IP Dst's:".ljust(20).foreground(:magenta).bright + "#{tcp_count}".rjust(25).foreground(:magenta).bright
  puts "Src IP, Dst IP:".ljust(20).foreground(:magenta).bright + "#{tcp_count}".rjust(25).foreground(:magenta).bright
  

  ### Print ICMP banner
  title = "[+] ICMP Protocol Breakdown '#{pcap}'".foreground(:white).bright
  puts "-" * title.size
  puts title
  puts "-" * title.size

	pcapd.each do |pkt|
  v = PacketFu::Packet.parse(pkt)

  # Print ICMP details to user
  puts "Packets:".ljust(20).foreground(:magenta).bright + "#{icmp_count}".rjust(25).foreground(:magenta).bright
  #system `tshark -r | grep ICMP >> one.txt` << "#{v}" 
 # exec('tshark -r "#{v}"')  # The file "#{v}" doesn't exist.
  %x( tshark -r #{v})

	puts "IP Dst's:".ljust(20).foreground(:magenta).bright + "#{icmp_count}".rjust(25).foreground(:magenta).bright
  puts "Popular IP Dst's:".ljust(20).foreground(:magenta).bright + "#{icmp_count}".rjust(25).foreground(:magenta).bright
  puts "Src IP, Dst IP:".ljust(20).foreground(:magenta).bright + "#{icmp_count}".rjust(25).foreground(:magenta).bright
	end