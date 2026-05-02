#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'colorize'
require 'openssl'
require 'timeout'

# -------------------------------------------------------------------
# Lyussfyuring002 :: NiktoScan
# Nikto-style web scanner in Ruby
# target: Arch Linux / Kali Linux
# -------------------------------------------------------------------

module Lyuss
  module NiktoScan
    VERSION = '1.0.0'

    DANGEROUS_PATHS = %w[
      /admin /admin/ /administrator /wp-admin/ /phpmyadmin /phpmyadmin/
      /.git/HEAD /.git/config /.env /.env.local /.env.production
      /config.php /config.yml /config.yaml /config.json
      /backup /backup.zip /backup.tar.gz /db.sql /dump.sql
      /server-status /server-info /nginx_status
      /actuator /actuator/health /actuator/env /actuator/beans
      /api /api/v1 /api/v2 /api/swagger /swagger /swagger-ui.html
      /xmlrpc.php /wp-config.php /wp-config.php.bak
      /robots.txt /sitemap.xml /.htaccess /.htpasswd
      /crossdomain.xml /clientaccesspolicy.xml
      /trace /TRACE /__debug__/ /console
      /cgi-bin/ /cgi-bin/test.cgi /cgi-bin/php.cgi
    ].freeze

    INJECTION_PATHS = [
      "/?id=1'",
      '/?q=1 OR 1=1--',
      '/?search=../../../etc/passwd',
      '/?file=../../../../etc/shadow',
      "/?cmd=;id",
      '/?url=http://169.254.169.254/latest/meta-data/',
    ].freeze

    HEADER_CHECKS = {
      'X-Frame-Options'         => :medium,
      'X-Content-Type-Options'  => :low,
      'Content-Security-Policy' => :medium,
      'Strict-Transport-Security' => :high,
      'X-XSS-Protection'        => :low,
      'Referrer-Policy'         => :low,
      'Permissions-Policy'      => :low,
    }.freeze

    class Finding
      attr_reader :severity, :category, :detail, :evidence

      def initialize(severity, category, detail, evidence = nil)
        @severity = severity
        @category = category
        @detail   = detail
        @evidence = evidence
      end

      def to_h
        { severity: @severity, category: @category, detail: @detail, evidence: @evidence }
      end
    end

    class Scanner
      attr_reader :findings

      def initialize(target, opts = {})
        @uri      = URI.parse(target.start_with?('http') ? target : "http://#{target}")
        @target   = target
        @timeout  = opts.fetch(:timeout, 10)
        @output   = opts.fetch(:output, nil)
        @findings = []
      end

      def run
        print_banner
        check_headers
        check_dangerous_paths
        check_methods
        check_injection_probes
        print_summary
        write_output if @output
      end

      private

      def get(path, method: :get)
        uri = @uri.dup
        uri.path  = path.split('?').first
        uri.query = path.include?('?') ? path.split('?', 2).last : nil

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = @timeout
        http.read_timeout = @timeout

        req_class = method == :options ? Net::HTTP::Options : Net::HTTP::Get
        req = req_class.new(uri.request_uri)
        req['User-Agent'] = 'Lyussfyuring002/NiktoScan 1.0'

        Timeout.timeout(@timeout) { http.request(req) }
      rescue => _e
        nil
      end

      def add(severity, category, detail, evidence = nil)
        f = Finding.new(severity, category, detail, evidence)
        @findings << f

        color = case severity
                when :critical then :light_red
                when :high     then :red
                when :medium   then :yellow
                when :low      then :cyan
                else           :white
                end

        sev_tag = "[#{severity.to_s.upcase}]".colorize(color)
        puts "  #{sev_tag} [#{category}] #{detail}"
        puts "         evidence: #{evidence}".colorize(:light_black) if evidence
      end

      def check_headers
        puts "\n#{'=' * 60}"
        puts '[*] checking security headers...'.colorize(:cyan)

        resp = get('/')
        return unless resp

        HEADER_CHECKS.each do |header, sev|
          unless resp[header]
            add(sev, 'HEADERS', "missing header: #{header}")
          end
        end

        if resp['Server'] && !resp['Server'].empty?
          add(:low, 'DISCLOSURE', 'server version disclosed', resp['Server'])
        end

        if resp['X-Powered-By'] && !resp['X-Powered-By'].empty?
          add(:low, 'DISCLOSURE', 'X-Powered-By disclosed', resp['X-Powered-By'])
        end
      end

      def check_dangerous_paths
        puts "\n[*] probing #{DANGEROUS_PATHS.size} known dangerous paths...".colorize(:cyan)

        DANGEROUS_PATHS.each do |path|
          resp = get(path)
          next unless resp

          case resp.code.to_i
          when 200
            add(:high, 'PATH', "accessible: #{path}", "HTTP 200")
          when 301, 302, 307, 308
            add(:medium, 'PATH', "redirect from: #{path}", "HTTP #{resp.code} -> #{resp['Location']}")
          when 401, 403
            add(:low, 'PATH', "auth-protected: #{path}", "HTTP #{resp.code}")
          end
        end
      end

      def check_methods
        puts "\n[*] testing dangerous HTTP methods...".colorize(:cyan)

        resp = get('/', method: :options)
        return unless resp

        allow = resp['Allow'] || resp['Public'] || ''
        %w[PUT DELETE TRACE CONNECT PATCH].each do |m|
          if allow.upcase.include?(m)
            sev = %w[TRACE CONNECT PUT DELETE].include?(m) ? :high : :medium
            add(sev, 'METHODS', "dangerous method allowed: #{m}", allow)
          end
        end
      end

      def check_injection_probes
        puts "\n[*] probing injection vectors...".colorize(:cyan)

        INJECTION_PATHS.each do |path|
          resp = get(path)
          next unless resp

          body = resp.body.to_s.downcase
          code = resp.code.to_i

          if code == 500
            add(:high, 'INJECTION', "server error on probe (possible injection)", path)
          end

          if body.include?('root:') || body.include?('/bin/bash')
            add(:critical, 'LFI', 'possible LFI - /etc/passwd content detected', path)
          end

          if body.include?('sql syntax') || body.include?('mysql_fetch') || body.include?('syntax error')
            add(:high, 'SQLI', 'SQL error in response (possible SQLi)', path)
          end
        end
      end

      def print_banner
        puts <<~BANNER.colorize(:magenta)
          ================================================
          Lyussfyuring002 :: NiktoScan v#{VERSION}
          target : #{@uri}
          ================================================
        BANNER
      end

      def print_summary
        puts "\n#{'=' * 60}"
        crit  = @findings.count { |f| f.severity == :critical }
        high  = @findings.count { |f| f.severity == :high }
        med   = @findings.count { |f| f.severity == :medium }
        low   = @findings.count { |f| f.severity == :low }

        puts "[+] scan complete: #{@findings.size} findings".colorize(:green)
        puts "    critical=#{crit}  high=#{high}  medium=#{med}  low=#{low}"
        puts '=' * 60
      end

      def write_output
        data = @findings.map(&:to_h)
        File.write(@output, JSON.pretty_generate({ target: @target, findings: data }))
        puts "[*] results written to: #{@output}".colorize(:cyan)
      end
    end
  end
end

# ---- CLI entry point ----
if __FILE__ == $PROGRAM_NAME
  options = { timeout: 10 }

  OptionParser.new do |opts|
    opts.banner = 'Usage: nikto_scan.rb [options] <target>'
    opts.on('-o', '--output FILE', 'JSON output file') { |v| options[:output] = v }
    opts.on('-t', '--timeout N',  Integer, 'request timeout (default 10)') { |v| options[:timeout] = v }
  end.parse!

  target = ARGV.shift
  if target.nil? || target.empty?
    warn 'error: target URL required'.colorize(:red)
    exit 1
  end

  scanner = Lyuss::NiktoScan::Scanner.new(target, options)
  scanner.run
end
