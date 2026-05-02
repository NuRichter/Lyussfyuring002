#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'resolv'
require 'optparse'
require 'colorize'
require 'set'

# -------------------------------------------------------------------
# Lyussfyuring002 :: MaltegoMap
# Maltego-style OSINT entity graph mapper in Ruby
# target: Arch Linux / Kali Linux
# -------------------------------------------------------------------

module Lyuss
  module MaltegoMap
    VERSION = '1.0.0'

    class Entity
      attr_accessor :type, :value, :properties, :links

      TYPES = %i[domain ip email subdomain asn person org url phone].freeze

      def initialize(type, value, props = {})
        raise ArgumentError, "unknown entity type: #{type}" unless TYPES.include?(type)
        @type       = type
        @value      = value
        @properties = props
        @links      = []
      end

      def link_to(other, label = nil)
        @links << { entity: other, label: label }
      end

      def to_h
        {
          type:  @type,
          value: @value,
          props: @properties,
          links: @links.map { |l| { to: l[:entity].value, label: l[:label] } },
        }
      end

      def to_s
        "[#{@type.upcase}] #{@value}"
      end
    end

    class Graph
      attr_reader :entities

      def initialize
        @entities = {}
      end

      def add(type, value, props = {})
        key = "#{type}:#{value}"
        @entities[key] ||= Entity.new(type, value, props)
      end

      def get(type, value)
        @entities["#{type}:#{value}"]
      end

      def link(from_type, from_val, to_type, to_val, label = nil)
        src = add(from_type, from_val)
        dst = add(to_type, to_val)
        src.link_to(dst, label)
      end

      def export_json
        @entities.values.map(&:to_h)
      end

      def print_tree
        @entities.values.each do |e|
          puts "  #{e}"
          e.links.each do |l|
            puts "    +-- [#{l[:label] || 'linked'}] #{l[:entity]}"
          end
        end
      end
    end

    class Mapper
      def initialize(seed_domain, opts = {})
        @domain  = seed_domain.downcase.strip
        @depth   = opts.fetch(:depth, 2)
        @output  = opts.fetch(:output, nil)
        @graph   = Graph.new
        @visited = Set.new
        @client  = Net::HTTP
      end

      def run
        print_banner
        map_domain(@domain, current_depth: 0)
        print_results
        write_output if @output
      end

      private

      def map_domain(domain, current_depth:)
        return if @visited.include?(domain) || current_depth > @depth
        @visited << domain

        puts "\n[*] mapping: #{domain}".colorize(:cyan)

        dom_entity = @graph.add(:domain, domain)

        resolve_ips(domain)
        resolve_mx(domain)
        resolve_ns(domain)
        cert_transparency(domain)

        @graph.entities.select { |_k, v| v.type == :subdomain }.each_value do |sub|
          next if @visited.include?(sub.value)
          @graph.link(:domain, domain, :subdomain, sub.value, 'subdomain')
          map_domain(sub.value, current_depth: current_depth + 1) if current_depth < @depth
        end
      end

      def resolve_ips(domain)
        ips = Resolv::DNS.new.getresources(domain, Resolv::DNS::Resource::IN::A)
        ips.each do |r|
          ip = r.address.to_s
          @graph.add(:ip, ip)
          @graph.link(:domain, domain, :ip, ip, 'A record')
          puts "  [A]    #{ip}".colorize(:green)
        end
      rescue Resolv::ResolvError => _e
        # silent
      end

      def resolve_mx(domain)
        Resolv::DNS.new.getresources(domain, Resolv::DNS::Resource::IN::MX).each do |r|
          host = r.exchange.to_s.chomp('.')
          @graph.add(:subdomain, host, { record: 'MX', priority: r.preference })
          @graph.link(:domain, domain, :subdomain, host, 'MX record')
          puts "  [MX]   #{host} (prio #{r.preference})".colorize(:yellow)
        end
      rescue Resolv::ResolvError => _e
        # silent
      end

      def resolve_ns(domain)
        Resolv::DNS.new.getresources(domain, Resolv::DNS::Resource::IN::NS).each do |r|
          host = r.name.to_s.chomp('.')
          @graph.add(:subdomain, host, { record: 'NS' })
          @graph.link(:domain, domain, :subdomain, host, 'NS record')
          puts "  [NS]   #{host}".colorize(:yellow)
        end
      rescue Resolv::ResolvError => _e
        # silent
      end

      def cert_transparency(domain)
        uri = URI.parse("https://crt.sh/?q=%.#{domain}&output=json")
        resp = Net::HTTP.get_response(uri)
        return unless resp.is_a?(Net::HTTPSuccess)

        entries = JSON.parse(resp.body)
        entries.each do |e|
          name = e['name_value'].to_s.downcase
          name.split("\n").each do |sub|
            sub = sub.gsub(/^\*\./, '').strip
            next if sub.empty? || sub == domain || @graph.get(:subdomain, sub)
            @graph.add(:subdomain, sub, { source: 'crt.sh' })
            @graph.link(:domain, domain, :subdomain, sub, 'cert transparency')
            puts "  [CRT]  #{sub}".colorize(:magenta)
          end
        end
      rescue => _e
        # silent
      end

      def print_banner
        puts <<~BANNER.colorize(:magenta)
          ================================================
          Lyussfyuring002 :: MaltegoMap v#{VERSION}
          seed  : #{@domain}
          depth : #{@depth}
          ================================================
        BANNER
      end

      def print_results
        puts "\n#{'=' * 60}"
        puts '[+] entity graph:'.colorize(:green)
        @graph.print_tree

        types = @graph.entities.values.group_by(&:type)
        puts "\n[+] summary:".colorize(:green)
        types.each { |type, ents| puts "    #{type}: #{ents.size}" }
        puts '=' * 60
      end

      def write_output
        data = {
          seed:     @domain,
          entities: @graph.export_json,
        }
        File.write(@output, JSON.pretty_generate(data))
        puts "[*] graph written to: #{@output}".colorize(:cyan)
      end
    end
  end
end

# ---- CLI entry point ----
if __FILE__ == $PROGRAM_NAME
  options = { depth: 2 }

  OptionParser.new do |opts|
    opts.banner = 'Usage: maltego_map.rb [options] <domain>'
    opts.on('-d', '--depth N',  Integer, 'recursion depth (default 2)')  { |v| options[:depth] = v }
    opts.on('-o', '--output F', String,  'JSON output file')             { |v| options[:output] = v }
  end.parse!

  domain = ARGV.shift
  if domain.nil? || domain.empty?
    warn 'error: seed domain required'.colorize(:red)
    exit 1
  end

  mapper = Lyuss::MaltegoMap::Mapper.new(domain, options)
  mapper.run
end
