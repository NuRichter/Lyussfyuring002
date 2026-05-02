#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'colorize'

# -------------------------------------------------------------------
# Lyussfyuring002 :: OSINTFramework
# OSINT source aggregator and query dispatcher in Ruby
# target: Arch Linux / Kali Linux
# -------------------------------------------------------------------

module Lyuss
  module OSINTFramework
    VERSION = '1.0.0'

    SOURCES = {
      username: {
        'GitHub'     => 'https://github.com/%s',
        'GitLab'     => 'https://gitlab.com/%s',
        'Twitter'    => 'https://twitter.com/%s',
        'Instagram'  => 'https://instagram.com/%s',
        'Reddit'     => 'https://reddit.com/user/%s',
        'HackerNews' => 'https://news.ycombinator.com/user?id=%s',
        'Keybase'    => 'https://keybase.io/%s',
        'Dev.to'     => 'https://dev.to/%s',
        'TryHackMe'  => 'https://tryhackme.com/p/%s',
        'HackTheBox' => 'https://app.hackthebox.com/users/search?term=%s',
      },
      email: {
        'HaveIBeenPwned' => 'https://haveibeenpwned.com/account/%s',
        'Hunter.io'      => 'https://hunter.io/email-verifier/%s',
        'Emailrep'       => 'https://emailrep.io/%s',
        'GHSearch'       => 'https://github.com/search?q=%s&type=commits',
      },
      domain: {
        'Shodan'      => 'https://www.shodan.io/search?query=%s',
        'VirusTotal'  => 'https://www.virustotal.com/gui/domain/%s',
        'Censys'      => 'https://search.censys.io/search?resource=hosts&q=%s',
        'crt.sh'      => 'https://crt.sh/?q=%%25.%s',
        'URLScan'     => 'https://urlscan.io/search/#domain:%s',
        'DNSDumpster' => 'https://dnsdumpster.com',
        'SecurityTrails' => 'https://securitytrails.com/domain/%s/records',
        'Wayback'     => 'https://web.archive.org/web/*/%s',
        'RiskIQ'      => 'https://community.riskiq.com/search/%s',
      },
      ip: {
        'Shodan'     => 'https://www.shodan.io/host/%s',
        'AbuseIPDB'  => 'https://www.abuseipdb.com/check/%s',
        'IPInfo'     => 'https://ipinfo.io/%s',
        'GreyNoise'  => 'https://www.greynoise.io/viz/ip/%s',
        'Censys'     => 'https://search.censys.io/hosts/%s',
        'IPVoid'     => 'https://www.ipvoid.com/ip-blacklist-check/?ip=%s',
        'ThreatBook' => 'https://threatbook.io/ip/%s',
      },
    }.freeze

    class Dispatcher
      def initialize(type, query, opts = {})
        @type   = type.to_sym
        @query  = query.strip
        @check  = opts.fetch(:check, false)
        @output = opts.fetch(:output, nil)
        @results = []
      end

      def run
        print_banner
        dispatch_sources
        print_summary
        write_output if @output
      end

      private

      def dispatch_sources
        sources = SOURCES[@type]
        if sources.nil?
          warn "unknown type: #{@type}. valid: #{SOURCES.keys.join(', ')}".colorize(:red)
          return
        end

        puts "\n[*] OSINT sources for #{@type.upcase}: #{@query}".colorize(:cyan)
        puts '-' * 64

        sources.each do |name, url_template|
          url = url_template % @query
          result = { source: name, url: url, status: nil }

          if @check
            status = probe(url)
            result[:status] = status
            color = status == 200 ? :green : :light_black
            puts "  [#{status || 'ERR'}] #{name.ljust(18)} #{url}".colorize(color)
          else
            puts "  [URL] #{name.ljust(18)} #{url}".colorize(:cyan)
          end

          @results << result
        end
      end

      def probe(url)
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = 6
        http.read_timeout = 6
        req = Net::HTTP::Get.new(uri.request_uri)
        req['User-Agent'] = 'Mozilla/5.0 (Lyussfyuring002/OSINT)'
        resp = http.request(req)
        resp.code.to_i
      rescue => _e
        nil
      end

      def print_banner
        puts <<~BANNER.colorize(:magenta)
          ================================================
          Lyussfyuring002 :: OSINTFramework v#{VERSION}
          type  : #{@type}
          query : #{@query}
          ================================================
        BANNER
      end

      def print_summary
        puts "\n#{'=' * 64}"
        puts "[+] #{@results.size} sources dispatched for [#{@type}] #{@query}".colorize(:green)
        if @check
          hits = @results.count { |r| r[:status] == 200 }
          puts "    active (200): #{hits}"
        end
        puts '=' * 64
      end

      def write_output
        data = { type: @type, query: @query, results: @results }
        File.write(@output, JSON.pretty_generate(data))
        puts "[*] results written to: #{@output}".colorize(:cyan)
      end
    end
  end
end

# ---- CLI entry point ----
if __FILE__ == $PROGRAM_NAME
  options = { check: false }

  OptionParser.new do |opts|
    opts.banner = 'Usage: osint_framework.rb [options] <query>'
    opts.on('-t', '--type TYPE',   'entity type: username|email|domain|ip') { |v| options[:type] = v }
    opts.on('-c', '--check',       'probe each URL for HTTP 200')           { options[:check] = true }
    opts.on('-o', '--output FILE', 'JSON output file')                      { |v| options[:output] = v }
  end.parse!

  query = ARGV.shift
  if query.nil? || query.empty? || options[:type].nil?
    warn 'error: --type and query are required'.colorize(:red)
    exit 1
  end

  dispatcher = Lyuss::OSINTFramework::Dispatcher.new(options[:type], query, options)
  dispatcher.run
end
