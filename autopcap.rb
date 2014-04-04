#!/usr/bin/env ruby
require 'packetfu'; require 'rainbow'
 
# TO-DO
# Fix - Raise RuntimeError, "Need an infile, like so: #{$0} in.pcap" when no argv is given

file = ARGV[0] || exit
tcp_count = 0

def print_results(stats)
  stats.each_pair { |k,v| puts "%-12s: %10d" % [k,v] }
end

# Takes a file name, parses the packets, and records the packet
# type based on its PacketFu class.
def count_packet_types(file)
  stats = {}
  count = 0
  elapsed = 0
  start_time = Time.now
  PacketFu::PcapFile.read_packets(file) do |pkt|
    kind = pkt.proto.last.to_sym
    stats[kind] ? stats[kind] += 1 : stats[kind] = 1
    count += 1
    elapsed = (Time.now - start_time).to_i
    if count % 5_000 == 0
      puts "After #{count} packets (#{elapsed} seconds elapsed):"
      print_results(stats)
    end
  end
  puts "Final results for #{count} packets (#{elapsed} seconds elapsed):"
  print_results(stats)
end

if File.readable?(infile = (ARGV[0] || 'in.pcap'))
  title = "Packets by packet type in '#{infile}'".foreground(:white).bright
  puts "-" * title.size
  puts title
  puts "-" * title.size
  count_packet_types(infile)
else
  raise RuntimeError, "Need an infile, like so: #{$0} in.pcap"
end

    # if pkt.is_tcp?
    #    tcp_count += 1
		# end

  ### Create file to store results
  x = File.new('results.txt', 'w')
	#x.puts "TCP total connections: #{count}"

  ### TCP banner
  title = "[+] TCP Protocol Breakdown '#{infile}'".foreground(:white).bright
  puts "-" * title.size
  puts title
  puts "-" * title.size
	x.puts "\n(source ipaddr port) => (dest ipaddr port)".foreground(:yellow).bright
	puts "\n(source ipaddr port) => (dest ipaddr port)".foreground(:yellow).bright

	PacketFu::PcapFile.read_packets(file) do |pkt|
#puts "TCP total connections\n\n"
#puts "TCP closed"
#puts "TCP open"
#puts "TCP filtered"
#puts "TCP Packets"

if pkt.is_ip? and pkt.is_tcp?
if pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 0
puts "#{pkt.ip_saddr}:#{pkt.tcp_sport}".ljust(25).foreground(:magenta).bright + "#{pkt.ip_daddr}:#{pkt.tcp_dport}".rjust(15).foreground(:magenta).bright
x.puts "#{pkt.ip_saddr}:#{pkt.tcp_sport}".ljust(25).foreground(:magenta).bright + "#{pkt.ip_daddr}:#{pkt.tcp_dport}".rjust(15).foreground(:magenta).bright

#x.close
#puts "Destination Addr: #{pkt.ip_daddr}\n"
#puts "Destination Port: #{pkt.tcp_dport}\n"
#puts "TCP Options: #{pkt.tcp_options}\n"
#puts "TCP SYN?: #{pkt.tcp_flags.syn}\n"
#puts "TCP ACK?: #{pkt.tcp_flags.ack}\n"
end
end
end
