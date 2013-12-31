#!/usr/bin/env ruby
require 'packetfu'; require 'rainbow'
# API dox http://planb-security.net/packetfu/doc/

# TO-DO:
# Get the src/dst ip parsing issues worked out
# Integrate into auto_snorter.rb
# See what else from a malware perspective makes sense to add as new features

# User supplies .pcap as an argument
pcap  = ARGV[0] || exit
count = 0
pcapd = PacketFu::Read.f2a(:file => pcap)   # alias for file_to_array
#processed_pcap = PacketFu::PcapFile.read.to_s(pcap) # does not work

# Parse / process the supplied .pcap
pcapd.each do |pkt|
v = PacketFu::Packet.parse(pkt)

# Begin packet count
count += 1
end

# Print packet count to user
title = "Packet attributes in '#{pcap}'".foreground(:white).bright
puts "-" * title.size
puts title
puts "-" * title.size

puts "#{count}".foreground(:magenta).bright + " packets".rjust(12).foreground(:magenta).bright # inop / fix

# Read file packets
r = PacketFu::PcapFile.read(pcap)

# Print packet size to user
puts "#{r}".size.to_s.foreground(:magenta).bright + " bytes\n".rjust(9).foreground(:magenta).bright # inop / fix

# Read Source IP's
#src = PacketFu::IPHeader.ip_saddr(pcap)

# Read Destination IP's
#dst = PacketFu::IPHeader.ip_daddr(pcap)

#puts src
#puts dst
