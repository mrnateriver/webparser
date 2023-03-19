# Copyright (c) 2016 Evgenii Dobrovidov
# This file is part of "WebParser".
#
# "WebParser" is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# "WebParser" is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with "WebParser".  If not, see <http://www.gnu.org/licenses/>.

require 'open-uri'
require 'net/http'
require 'addressable/uri'
require 'time'
require 'date'
require 'nokogiri'
require 'hpricot'
require 'unicode'
require 'pp'

class String
  def match_all(regex)
    match_str = self
    match_datas = []
    while match_str.length > 0 do
      md = match_str.match(regex)
      break unless md
      match_datas << md

      if md.post_match == match_str
        match_str.slice!(0)
      else
        match_str = md.post_match
      end
    end
    return match_datas
  end
end

class XPathFunctions
  def case_insensitive_equals(node_set, str_to_match)
    node_set.find_all {|node| node.to_s.downcase == str_to_match.to_s.downcase }
  end
end

module CSS
  extend self
  UNSUPPORTED = /(:first-letter|:link|:visited|:hover|:active)(\s|$)/

  def inline(args)
    css, doc = process(args)
    raw_styles(css).each do |raw_style|
      style, contents = parse(raw_style)
      next unless style or contents
      next if style.match(UNSUPPORTED)
      doc.search(style) do |element, arg2|
        apply_to(element, style, contents)
      end
    end
    if args[:prune_classes]
      (doc/"*").each { |e| e.remove_attribute(:class) if e.respond_to?(:remove_attribute) }
    end
    doc.to_s
  end

  private

  def process(args)
    return_value =
        if args[:document]
          doc = Hpricot(args[:document])
          style = (doc/"style").first
          [(style && style.inner_html), doc]
        else
          doc = Hpricot(args[:body])
          [args[:css], doc]
        end
    return_value
  end

  def raw_styles(css)
    return [] if css.nil?
    css.gsub!(/[\r\n]/, " ")
    css.gsub!(/\/\*.*?\*\//, "")
    validate(css)
    styles = css.strip.split("}").map { |style| style + "}" }
    styles.reverse
  end

  def validate(css)
    lefts = bracket_count(css, "{")
    rights = bracket_count(css, "}")
    if lefts != rights
      raise InvalidStyleException, "Found #{lefts} left brackets and #{rights} right brackets in:\n #{css}"
    end
  end

  def bracket_count(css, bracket)
    css.scan(Regexp.new(Regexp.escape(bracket))).size
  end

  def parse(raw_style)
    data = raw_style.match(/^\s*([^{]+?)\s*\{(.*)\}\s*$/)
    return nil if data.nil?
    data.captures.map { |s| s.strip }
  end

  def apply_to(element, style, contents)
    return unless element.respond_to?(:get_attribute)
    current_style = to_hash(element.get_attribute(:style))
    new_styles = to_hash(contents).merge(current_style)
    element.set_attribute(:style, prepare(new_styles))
  rescue Exception => e
    raise InvalidStyleException, "Trouble on style #{style} on element #{element}"
  end

  def to_hash(style)
    return {} if style.nil?
    hash = {}
    styles = style.strip.scan(/((?:\(.*\)|[^;])+)/).flatten
    pieces = styles.map { |s| s.strip.split(":", 2).map { |kv| kv.strip.gsub('"', "'") } }
    pieces.each do |key, value|
      hash[key] = value
    end
    hash
  end

  def prepare(style_hash)
    sorted_styles = style_hash.keys.sort.map { |key| key + ": " + style_hash[key] }
    sorted_styles.join("; ").strip + ";"
  end
end

class InvalidStyleException < Exception
end

module ParseFlags
  DONT_SHIFT_SEARCH_INDEX = 0
  DONT_OMIT_CRITERIAS = 1
  DONT_TRIM_DATA = 2
  SET_LAST_INDEX_AT_FIELD_START = 3
end

module WebParser
  class ParseData
    #@parse_data

    def self.fetch_data url, page_enc = nil
      data = nil
      begin
        cont = get_html_content url
        data = cont[0]
        cont_enc = cont[2]
      rescue => err
        raise "failed to open url to fetch ParseData, url: #{url}, error: #{err.message}"
      end
      data.encode! 'utf-8', page_enc || cont_enc || 'utf-8', :invalid => :replace, :undef => :replace, :replace => ' ' if data
      self.new data
    end

    def initialize data
      raise ArgumentError, "wrong type of argument: 'data' should be a string" unless data.is_a? String
      @parse_data = data
    end

    def data
      @parse_data
    end
  end

  class UrlPattern
    #@urls_array

    def initialize url, params
      #url should be a string, otherwise raise ArgumentError
      #params can be either an array of values to replace placeholders in url, or it can be a function that yields new values for placeholders (can be either a symbol or lambda)
      #this function should yield an array of values, which length should be no less than the number of placeholders in url, otherwise raise error
      #and if it's an array, then each of its values should be an array of values for each placeholder
      #if such array doesn't contain arrays in each item then it's packed into another array with single item, so that it's considered to replace only one placeholder
      raise ArgumentError, "wrong type of argument: 'url' should be a string" unless url.is_a? String

      @urls_array = []
      unless params.is_a? Array or params.is_a? Range
        urlProc = params
        unless urlProc.respond_to? :call
          begin
            urlProc = method urlProc.to_s
          rescue
            raise ArgumentError, "invalid generator method: '#{urlProc.to_s}' specified for pattern: #{url}"
          end
        end

        urlProc.call do |values|
          @urls_array << replace_placeholders(url, values)
        end
      else
        params = params.to_a if params.is_a? Range
        single = check_params_array params
        raise ArgumentError, "invalid placeholder values array specified for pattern: #{url}" if single.nil?

        params = params.map { |value| [value] } if single #don't use map! because it will alter the object outside of this scope
        params.each do |values|
          @urls_array << replace_placeholders(url, values)
        end
      end
    end

    def each_url &block
      #yield each url
      @urls_array.each do |url|
        yield url
      end
    end

    private
    def replace_placeholders url, values
      if !url.is_a?(String) or !values.is_a?(Array)
        raise ArgumentError, "invalid data passed to replace placeholders"
      end
      #check if it contains placeholders and replace them with data if it does
      placeholders = []
      url.scan(/(?<=\$)(?<!\$\$)[0-9]*(?=;)/) do |placeholder|
        placeholders << placeholder unless placeholders.include? placeholder
      end
      placeholders.each do |placeholder|
        index = placeholder.to_i
        next if index.to_s != placeholder #this means it's not a correct integer

        raise ArgumentError, "invalid placeholder index specified for url pattern: #{url}" if values.size <= index or index < 0
        url = url.gsub "$#{placeholder};", values[index].to_s #don't use gsub! because it will alter the object outside of this scope
      end
      url
    end

    def check_params_array values
      return nil unless values.is_a? Array
      single = nil
      values.each do |item|
        unless single
          single = item.is_a?(Array) ? false : true
          next
        end
        if item.is_a?(Array) and single
          return nil
        elsif !item.is_a?(Array) and !single
          return nil
        end
      end
      single
    end
  end

  class XPathSelector
    #@selector
    #@parser
    def initialize sel, parser
      @selector = sel
      @parser = parser
    end
    attr_reader :selector
    attr_reader :parser
  end
  CSSSelector = XPathSelector.dup

  class ClosingTagSelector
    #@selector
    def initialize sel
      @selector = sel
    end
    attr_reader :selector
  end

  class WebContent
    #@url
    #@rules
    #@options

    def set_params url, params, optional = nil
      unless (params.is_a?(Hash) or params.is_a?(Array) or params.is_a?(XPathSelector) or params.is_a?(CSSSelector)) or (url.is_a?(String) or url.is_a?(Symbol) or url.is_a?(UrlPattern) or url.is_a?(Array) or url.is_a?(ParseData))
        raise ArgumentError, "wrong types of arguments"
      end
      #unless ((params.is_a?(Array) or params.is_a?(XPathSelector) or params.is_a?(CSSSelector)) and url.is_a?(Symbol)) or ((url.is_a?(String) or url.is_a?(Symbol) or url.is_a?(UrlPattern) or url.is_a?(Array) or url.is_a?(ParseData)) and (params.is_a?(Hash) or params.is_a?(Array)))
      #  raise ArgumentError, "wrong types of arguments"
      #end

      @url = url
      @rules = params
      @options = optional

      self
    end

    #available options:
    #:next                          #rules to parse link to next page each time
    #:trim_data                     #whether to remove trailing spaces for each value
    #:omit_criterias_from_result    #whether to remove strings from result that were used to find value
    #:allow_empty_values            #whether to allow or not empty values for fields
    #:source_encoding               #source pages encoding
    #:max_items_per_page            #maximum number of items that are parsed on each page
    #:errors_dump_threshold         #number of errors (such as not found entry start or end) before program execution is halted and content is dumped
    #:cleanup_by_fields             #an array of fields by which the end result is cleaned up - that is all entries that have these fields empty or nil are removed
    #:sql_dump_file                 #a file where the output result will be dumped
    #:sql_dump_table                #a mysql table for which insert queries will be generated
    #:content_anchor                #rules to parse the whole content to get data to get entries from
    #:pause_between_pages           #number of seconds before parsing pages
    def option opt
      @options[opt] if @options
    end
    def set_option opt, val = nil
      if val
        if @options
          @options[opt] = val
        else
          @options = {opt => val}
        end
      else
        @options = opt
      end
    end

    def parse_content parent_data = nil, field_flags = nil, parse_url = nil
      url_empty_flag = false
      unless parse_url
        parse_url = @url
        url_empty_flag = true
      end
      result = []
      if parse_url.is_a? ParseData
        if (@rules.is_a? Array and @rules.size > 1) or (@rules.is_a?(XPathSelector) or @rules.is_a?(CSSSelector))
          begin
            result = parse_page_for_single_result parse_url, @rules
          rescue => e
            $stderr.puts "unable to parse single content, error: #{e.message}"
            return nil
          end
        else
          curUrl = "nil" #just so that while loop gets executed at least once
          while curUrl
            res = process_url curUrl, parse_url
            result += res[0] if res and res[0]
            curUrl = res[1] #get :next link
            sleep(option(:pause_between_pages)) if option :pause_between_pages
          end
        end
      elsif parse_url.is_a? UrlPattern
        parse_url.each_url { |url|
          curUrl = url
          while curUrl
            res = process_url curUrl
            result += res[0] if res and res[0]
            curUrl = res[1] #get :next link
            sleep(option(:pause_between_pages)) if option :pause_between_pages
          end
        }
      elsif parse_url.is_a? Array
        parse_url.each { |url|
          res = parse_content parent_data, field_flags, url
          result += res if res
          sleep(option(:pause_between_pages)) if option :pause_between_pages
        }
      elsif parse_url.is_a? Symbol
        raise ArgumentError, "no data is passed to inner WebContent" unless parent_data and parent_data.is_a? Hash
        #go through parent_data, find necessary field and pass it to process_url
        url = parent_data[parse_url.to_s] || parent_data[parse_url]
        unless url
          $stderr.puts "can't find url in parent data for reading inner WebContent, specified url: #{parse_url}"
          return nil
        end
        begin
          puts "parsing inner content with url: #{url}"
          result = parse_page_for_single_result url, @rules, parent_data, field_flags
        rescue => e
          $stderr.puts "unable to parse inner content, error: #{e.message}"
          return nil
        end
        puts "inner WebContent parsed successfully!" if result
      else
        if (@rules.is_a? Array and @rules.size > 1) or (@rules.is_a?(XPathSelector) or @rules.is_a?(CSSSelector))
          begin
            result = parse_page_for_single_result parse_url, @rules
          rescue => e
            $stderr.puts "unable to parse single content, error: #{e.message}"
            return nil
          end
        else
          curUrl = parse_url
          while curUrl
            res = process_url curUrl

            result += res[0] if res and res[0]
            curUrl = res[1] #get :next link
            sleep(option(:pause_between_pages)) if option :pause_between_pages
          end
        end
      end
      unless parse_url.is_a?(String) and ((@rules.is_a? Array and @rules.size > 1) or (@rules.is_a?(XPathSelector) or @rules.is_a?(CSSSelector)))
        if !parse_url.is_a? Symbol and url_empty_flag
          if option(:cleanup_by_fields)
            result.delete_if do |item|
              fail = false
              option(:cleanup_by_fields).each do |field|
                if !item[field] or item[field].size <= 0
                  fail = true
                  break
                end
              end
              fail
            end
          end
          if option(:sql_dump_file) and option(:sql_dump_table)
            File.open(option(:sql_dump_file), 'w') do |f|
              result.each do |row|
                query = "INSERT INTO #{option(:sql_dump_table)} ("
                values = ""
                row.each do |key, value|
                  next if key.is_a? Symbol or !key

                  query << '`' << key.to_s << '`,'

                  val = value.to_s
                  values << '\'' << escape_sql_string(val) << '\','
                end
                query.chomp! ','
                values.chomp! ','

                query << ") VALUES (" << values << ");"
                f.puts query
              end
            end
          end
        end
      end
      result
    end

    private
    def parse_page_for_single_result url, criterias, parent_data = {}, field_flags = []
      unless url and criterias and ((criterias.is_a? Array and criterias.size > 1) or @rules.is_a?(XPathSelector) or @rules.is_a?(CSSSelector))
        raise "wrong arguments passed for parse_page_for_single_result"
      end
      last_parsed_url = nil
      if url.is_a? ParseData
        data = url.data
      else
        last_parsed_url = url
        begin
          cont = get_html_content url
          data = cont[0]
          last_parsed_url = cont[1]
          cont_enc = cont[2]
        rescue => err
          raise "failed to open url for parsing page for single result, url: #{url}, error: #{err.message}"
        end
        data.encode! 'utf-8', option(:source_encoding) || cont_enc || 'utf-8', :invalid => :replace, :undef => :replace, :replace => ' '
      end

      result = nil
      if criterias and criterias.is_a?(Array) and criterias.size > 1
        dataStartCriteria = resolve_criteria(criterias[0], parent_data)
        dataEndCriteria = nil
        if criterias[1].is_a? ClosingTagSelector
          dataEndCriteria = criterias[1]
        else
          dataEndCriteria = resolve_criteria(criterias[1], parent_data)
        end
        unless dataStartCriteria and dataEndCriteria
          raise "couldn't resolve search criterias for parsing page for single result"
        end

        parser_proc = nil
        if criterias.size > 2
          parser_proc = criterias[2]
          unless parser_proc.respond_to? :call
            begin
              parser_proc = method parser_proc.to_s
            rescue
              $stderr.puts "invalid parser method: '#{parser_proc.to_s}' specified for parsing page for single result, url: #{parse_url}"
              parser_proc = nil
            end
          end
        end

        pdata = parent_data.clone
        pdata[:parsed_url] = last_parsed_url if last_parsed_url
        pdata[:html_data] = data

        result = process_single_result data, dataStartCriteria, dataEndCriteria, parser_proc, (option(:trim_data) and !field_flags.include?(ParseFlags::DONT_TRIM_DATA)), pdata, field_flags
      elsif criterias and (criterias.is_a?(XPathSelector) or criterias.is_a?(CSSSelector))
        doc = Nokogiri::HTML(data)
        if doc
          if criterias.is_a?(XPathSelector)
            result = doc.xpath(criterias.selector).first
          else
            result = doc.css(criterias.selector).first
          end
          if result
            unless option(:omit_criterias_from_result) or field_flags.include? ParseFlags::DONT_OMIT_CRITERIAS
              result = result.to_html
            else
              result = result.inner_html
            end
            parser_proc = criterias.parser
            if parser_proc and !parser_proc.respond_to?(:call)
              begin
                parser_proc = method parser_proc.to_s
              rescue
                $stderr.puts "invalid parser method: '#{parser_proc.to_s}' specified for inner WebContent with url: #{@url}"
                parser_proc = nil
              end
            end
            pdata = parent_data.clone
            pdata[:parsed_url] = last_parsed_url if last_parsed_url
            pdata[:html_data] = data
            result = parser_proc.call result, pdata if parser_proc
          else
            $stderr.puts "couldn't find data with CSS/XPath criteria: #{criterias.selector}"
          end
        else
          raise "unable to create DOM structure from HTML code"
        end
      else
        raise "invalid format provided in parse rules for inner WebContent with url: #{url}"
      end
      result
    end

    def resolve_criteria criteria, entry
      if criteria.is_a? Symbol
        unless entry.include? criteria
          $stderr.puts "undefined placeholder used for key: '#{criteria}'"
          return nil
        end
        criteria = entry[criteria]
        unless criteria.is_a? Regexp
          criteria = criteria.to_s
        end
      else
        regexp = criteria.is_a?(Regexp)
        criteria = criteria.to_s #sanitize it just in case

        #check if it contains placeholders and replace them with data if it does
        placeholders = []
        criteria.scan(/(?<=\$)(?<!\$\$)[a-zA-Z][a-zA-Z0-9_]*(?=;)/) do |placeholder|
          unless entry.include?(placeholder.to_sym) or entry.include?(placeholder)
            $stderr.puts "undefined placeholder used for key: '#{criteria}'"
            return nil
          end
          placeholders << placeholder unless placeholders.include? placeholder
        end
        placeholders.each do |placeholder|
          replacement = (entry[placeholder.to_sym] || entry[placeholder]).to_s
          replacement = Regexp.escape(replacement) if regexp

          criteria = criteria.gsub("$#{placeholder};", replacement).gsub("$$", "$") #don't use gsub! because it will alter the object outside of this scope
        end
        criteria = Regexp.new(criteria) if regexp
      end
      criteria
    end

    def process_single_result data, startCriteria, endCriteria, parserProc = nil, trim = false, parent_entry = nil, flags = nil
      return nil unless data.is_a? String
      flags = [] unless flags
      result = nil
      if (startCriteria.is_a?(String) or startCriteria.is_a?(Regexp)) and (endCriteria.is_a?(String) or endCriteria.is_a?(Regexp) or endCriteria.is_a?(ClosingTagSelector)) and (parserProc.respond_to?(:call) or !parserProc)
        openIndex = data.index(startCriteria, 0)
        #check if we found the data
        if openIndex
          afterOpenIndex = openIndex
          if option :omit_criterias_from_result and !flags.include? ParseFlags::DONT_OMIT_CRITERIAS
            if startCriteria.is_a? Regexp
              openIndex += data.match(startCriteria, 0).to_s.size
            else
              openIndex += startCriteria.size
            end
          end

          if endCriteria.is_a?(ClosingTagSelector)
            endCriteria = endCriteria.selector
            if startCriteria.is_a? Regexp
              afterOpenIndex += data.match(startCriteria, 0).to_s.size
            else
              afterOpenIndex += startCriteria.size
            end

            inline_level = 0
            while true
              firstCloseIndex = data.index(/<\/#{endCriteria}>/i, afterOpenIndex)
              firstOpenIndex = data.index(/<#{endCriteria}[^>]*>/i, afterOpenIndex)
              if (firstCloseIndex and !firstOpenIndex) or (firstCloseIndex and firstOpenIndex and (firstCloseIndex < firstOpenIndex))
                if inline_level < 1
                  cut = nil
                  unless option :omit_criterias_from_result or flags.include?(ParseFlags::DONT_OMIT_CRITERIAS)
                    lastIndex = firstCloseIndex + data.match(/<\/#{endCriteria}>/i, firstCloseIndex).to_s.size
                  else
                    lastIndex = firstCloseIndex
                  end
                  cut = data.slice(openIndex...lastIndex)

                  cut.strip! if trim
                  cut = parserProc.call cut, parent_entry if parserProc

                  result = cut
                  break
                else
                  afterOpenIndex = firstCloseIndex + data.match(/<\/#{endCriteria}>/i, firstCloseIndex).to_s.size
                  inline_level -= 1
                end
              elsif firstCloseIndex and firstOpenIndex
                afterOpenIndex = firstOpenIndex + data.match(/<#{endCriteria}[^>]*>/i, firstOpenIndex).to_s.size
                inline_level += 1
              else
                $stderr.puts "couldn't find data end for single result with closing tag criteria: #{endCriteria}, afterOpenIndex: #{afterOpenIndex}, firstCloseIndex: #{firstCloseIndex}, firstOpenIndex: #{firstOpenIndex}"
                break
              end
            end
          else
            lastIndex = data.index(endCriteria, openIndex)
            if lastIndex
              unless option :omit_criterias_from_result or flags.include? ParseFlags::DONT_OMIT_CRITERIAS
                if endCriteria.is_a? Regexp
                  lastIndex += data.match(endCriteria, openIndex).to_s.size
                else
                  lastIndex += endCriteria.size
                end
              end
              cut = data.slice(openIndex...lastIndex)

              cut.strip! if trim
              cut = parserProc.call cut, parent_entry if parserProc

              result = cut
            else
              $stderr.puts "couldn't find data end for single result with criteria: #{endCriteria}"
            end
          end
        else
          $stderr.puts "couldn't find data start for single result with criteria: #{startCriteria}"
        end
      else
        $stderr.puts "wrong type of arguments provided for processing single result: criterias should be strings or regexps and 'parserProc' should be any kind of callable object"
      end
      result
    end

    def process_url url, data = nil
      last_parsed_url = url
      unless data
        return [] unless url.is_a? String
        begin
          puts "parsing page: #{url}"

          cont = get_html_content url
          data = cont[0]
          last_parsed_url = cont[1]
          cont_enc = cont[2]

          raise "incorrect data" if data.size <= 0
        rescue => e
          $stderr.puts "failed to open url for reading, error: #{e.message || "<empty>"}"
          #raise e
          return []
        end
      else
        data = data.data
      end
      data.encode! 'utf-8', option(:source_encoding) || cont_enc || 'utf-8', :invalid => :replace, :undef => :replace, :replace => ' '

      content = []
      lastIndex = 0

      #File.open('test_data_dump.html', 'w') do |f|
      #  f.puts data
      #end

      if option(:content_anchor) and option(:content_anchor).is_a? Array
        data = process_single_result data, *option(:content_anchor)
      end

      errors = 0
      searchIndex = 0
      while true
        entry = { :parsed_url => last_parsed_url, :html_data => data }

        closeIndex = nil
        @rules.each_with_index do |(key, value), iteration|
          key_flags = []
          if key.is_a? Array
            if key.size == 2
              key_flags = key[1]
              key = key[0]
            else
              $stderr.puts "invalid key provided in parse rules, key: '#{key.to_s}'"
              next
            end
          end
          unless key.is_a? Symbol
            key = key.to_s #sanitize it just in case
            unless /^[a-zA-Z][a-zA-Z0-9_]*$/i =~ key
              $stderr.puts "invalid key provided in parse rules, key: '#{key}'"
              next
            end
          end

          case value
            when WebContent
              value.set_option @options
              res = value.parse_content(entry,key_flags)
              entry[key] = res if res
              next
            when Numeric, String, DateTime, Time
              entry[key] = value
              next
            when Symbol
              entry[key] = entry[value] if entry[value]
              next
            else
              if value.respond_to? :call
                res = value.call entry
                entry[key] = res if res
                next
              elsif !value.is_a?(Array) or value.size < 2
                $stderr.puts "invalid format provided in parse rules for key: '#{key}'"
                next
              end
          end

          parser_proc = nil
          if value.size > 2
            parser_proc = value[2]
            unless parser_proc.respond_to? :call
              begin
                parser_proc = method parser_proc.to_s
              rescue
                $stderr.puts "invalid parser method: '#{parser_proc.to_s}' specified for key: '#{key}'"
                parser_proc = nil
              end
            end
          end

          dataStartCriteria = resolve_criteria(value[0], entry)
          if value[1].is_a? ClosingTagSelector
            dataEndCriteria = value[1].selector
          else
            dataEndCriteria = resolve_criteria(value[1], entry)
          end
          next unless dataStartCriteria and dataEndCriteria

          #criterias are resolved, now do parsing
          openIndex = data.index(dataStartCriteria, lastIndex)
          #check if we found the data
          if openIndex
            firstIndex = lastIndex
            afterOpenIndex = openIndex
            fieldStartIndex = openIndex
            if option :omit_criterias_from_result and !key_flags.include?(ParseFlags::DONT_OMIT_CRITERIAS)
              if dataStartCriteria.is_a? Regexp
                openIndex += data.match(dataStartCriteria, lastIndex).to_s.size
              else
                openIndex += dataStartCriteria.size
              end
            end

            #find and set the start of next entry
            if !closeIndex
              unless option :omit_criterias_from_result or key_flags.include?(ParseFlags::DONT_OMIT_CRITERIAS)
                if dataStartCriteria.is_a? Regexp
                  closeIndex = data.index(dataStartCriteria, openIndex + data.match(dataStartCriteria, lastIndex).to_s.size) || -1 #-1 means there's no more entries
                else
                  closeIndex = data.index(dataStartCriteria, openIndex + dataStartCriteria.size) || -1 #-1 means there's no more entries
                end
              else
                closeIndex = data.index(dataStartCriteria, openIndex) || -1 #-1 means there's no more entries
              end
            elsif closeIndex >= 0 and openIndex > closeIndex
              $stderr.puts "couldn't find data for key: '#{key}' for entry: #{searchIndex}"
              errors += 1
              next
            end

            if value[1].is_a? ClosingTagSelector
              if dataStartCriteria.is_a? Regexp
                afterOpenIndex += data.match(dataStartCriteria, lastIndex).to_s.size
              else
                afterOpenIndex += dataStartCriteria.size
              end

              inline_level = 0
              while true
                firstCloseIndex = data.index(/<\/#{dataEndCriteria}>/i, afterOpenIndex)
                firstOpenIndex = data.index(/<#{dataEndCriteria}[^>]*>/i, afterOpenIndex)
                if (firstCloseIndex and !firstOpenIndex) or (firstCloseIndex and firstOpenIndex and (firstCloseIndex < firstOpenIndex))
                  if inline_level < 1
                    cut = nil
                    #difference is in order
                    if option :omit_criterias_from_result and !key_flags.include?(ParseFlags::DONT_OMIT_CRITERIAS)
                      cut = data.slice(openIndex...firstCloseIndex)
                      lastIndex = firstCloseIndex + data.match(/<\/#{dataEndCriteria}>/i, firstCloseIndex).to_s.size
                    else
                      lastIndex = firstCloseIndex + data.match(/<\/#{dataEndCriteria}>/i, firstCloseIndex).to_s.size
                      cut = data.slice(openIndex...lastIndex)
                    end

                    if closeIndex >= 0 and lastIndex > closeIndex
                      break
                    end

                    cut.strip! if option(:trim_data) and !key_flags.include?(ParseFlags::DONT_TRIM_DATA)
                    cut = parser_proc.call cut, entry if parser_proc

                    entry[key] = cut
                    break
                  else
                    afterOpenIndex = firstCloseIndex + data.match(/<\/#{dataEndCriteria}>/i, firstCloseIndex).to_s.size
                    inline_level -= 1
                  end
                elsif firstCloseIndex and firstOpenIndex
                  afterOpenIndex = firstOpenIndex + data.match(/<#{dataEndCriteria}[^>]*>/i, firstOpenIndex).to_s.size
                  inline_level += 1
                else
                  $stderr.puts "couldn't find data end for key: '#{key}' for entry: #{searchIndex}"
                  errors += 1
                  break
                end
              end
              if closeIndex >= 0 and lastIndex > closeIndex
                $stderr.puts "data end is only found after entry closing for key: '#{key}' for entry: #{searchIndex}, either input data is invalid or you've specified incorrect parsing rules"
                lastIndex = fieldStartIndex #set this so we don't miss next field or even entry
                errors += 1
                next
              end
            else
              lastIndex = data.index(dataEndCriteria, openIndex)
              if lastIndex
                cut = nil
                #difference is in order
                if option :omit_criterias_from_result and !key_flags.include?(ParseFlags::DONT_OMIT_CRITERIAS)
                  cut = data.slice(openIndex...lastIndex)
                  if dataEndCriteria.is_a? Regexp
                    lastIndex += data.match(dataEndCriteria, openIndex).to_s.size
                  else
                    lastIndex += dataEndCriteria.size
                  end
                else
                  if dataEndCriteria.is_a? Regexp
                    lastIndex += data.match(dataEndCriteria, openIndex).to_s.size
                  else
                    lastIndex += dataEndCriteria.size
                  end
                  cut = data.slice(openIndex...lastIndex)
                end

                if closeIndex >= 0 and lastIndex > closeIndex
                  $stderr.puts "data end is only found after entry closing for key: '#{key}' for entry: #{searchIndex}, either input data is invalid or you've specified incorrect parsing rules"
                  lastIndex = fieldStartIndex #set this so we don't miss next field or even entry
                  errors += 1
                  next
                end

                cut.strip! if option(:trim_data) and !key_flags.include?(ParseFlags::DONT_TRIM_DATA)
                cut = parser_proc.call cut, entry if parser_proc

                entry[key] = cut
              else
                $stderr.puts "couldn't find data end for key: '#{key}' for entry: #{searchIndex}"
                errors += 1
              end
            end
            if key_flags.include?(ParseFlags::DONT_SHIFT_SEARCH_INDEX)
              lastIndex = firstIndex
            end
            if key_flags.include?(ParseFlags::SET_LAST_INDEX_AT_FIELD_START)
              lastIndex = fieldStartIndex
            end
          else
            $stderr.puts "couldn't find data start for key: '#{key}' for entry: #{searchIndex}"
            errors += 1
          end
        end
        placeholders = []
        entry.each do |key, value|
          placeholders << key if key.is_a? Symbol
        end
        placeholders.each do |placeholder|
          entry.delete placeholder
        end

        if errors > (option(:errors_dump_threshold) || 3)
          $stderr.puts "error threshold is overcome after entry: #{searchIndex}, parsing url: #{url.to_s}, parsing data is dumped to 'error_data_dump.txt'!"
          File.open("./error_data_dump.txt", 'w') do |f|
            f.puts data
          end
          puts "press Enter if you wish to continue process..."
          gets
        end

        content << entry if option(:allow_empty_values) or entry.size > 0
        searchIndex += 1 if entry.size > 0

        break if (closeIndex and closeIndex < 0) or (option(:max_items_per_page) and searchIndex >= option(:max_items_per_page))
      end

      puts "page parsed! total entries: #{content.size}"

      #find :next link
      nextUrl = option :next
      if nextUrl
        if nextUrl.is_a?(Array) and nextUrl.size > 1
          parser_proc = nil
          if nextUrl.size > 2
            parser_proc = nextUrl[2]
            unless parser_proc.respond_to? :call
              begin
                parser_proc = method parser_proc.to_s
              rescue
                $stderr.puts "invalid parser method: '#{parser_proc.to_s}' specified for :next option"
                parser_proc = nil
              end
            end
          end
          nextUrl = process_single_result data, nextUrl[0], nextUrl[1], parser_proc, true
        elsif nextUrl.is_a?(XPathSelector) or nextUrl.is_a?(CSSSelector)
          doc = Nokogiri::HTML(data)
          if doc
            result = nil
            if nextUrl.is_a?(XPathSelector)
              result = doc.xpath(nextUrl.selector).first
            else
              result = doc.css(nextUrl.selector).first
            end
            result = result.text
            parser_proc = nextUrl.parser
            unless parser_proc.respond_to? :call
              begin
                parser_proc = method parser_proc.to_s
              rescue
                $stderr.puts "invalid parser method: '#{parser_proc.to_s}' specified for next link rule"
                parser_proc = nil
              end
            end
            nextUrl = parser_proc.call result, nil if parser_proc
          else
            $stderr.puts "unable to create DOM structure from HTML code for parsing next url"
            nextUrl = nil
          end
        else
          unless nextUrl.respond_to? :call
            begin
              nextUrl = method nextUrl.to_s
            rescue
              $stderr.puts "invalid data provided in parse rules for :next option"
              nextUrl = nil
            end
          end
          nextUrl = nextUrl.call content if nextUrl
        end
      end

      puts "parsed url for next page: #{nextUrl}" if nextUrl
      [content, nextUrl]
    end
  end

  #TODO: IMPLEMENT SETTING CONTENT_ANCHOR TO CSS OR XPATH
  #TODO: IMPROVE :PARSE_HTML_TEXT: REWRITE IMAGE PARSING TO USE HPRICOT AND ALSO DONT REMOVE ANCHORS THAT LEAD TO IMAGES - DOWNLOAD THOSE IMAGES AND ALTER ANCHORS
  #TODO: IMPLEMENT CSS/XPATH SELECTORS: ADD OPTION - :entry_anchor - IF IT'S SET TO XPATH OR CSS, THEN EACH ENTRY IS PARSED WITH IT AND ALL SELECTORS ARE APPLIED WITHIN IT, EVEN THOUGH HTML CODE MAY BE DIFFERENT DUE TO HPRICOT HANDLING
  #TODO: IMPLEMENT PARSING RULES, OPTIONS ETC FROM A HUMAN-READABLE FILE

  #return new UrlPattern and set its params
  def pattern url, params
    res = UrlPattern.new url, params
    res
  end

  #just convenience method
  def flags *args
    args
  end

  def xpath selector, parser = nil
    XPathSelector.new selector, parser
  end

  def css selector, parser = nil
    CSSSelector.new selector, parser
  end

  def closing_tag selector
    ClosingTagSelector.new selector
  end

  #call arg.parse_content, method simply to make calls look human-like
  def parse arg
    raise ArgumentError, "wrong type of argument: 'arg' should be an object of WebContent" unless arg.is_a? WebContent
    arg.parse_content
  end

  #return new WebContent and set its params
  def from src, rules, optional = nil
    res = WebContent.new
    res.set_params src, rules, optional
  end

  #downloads a file from specified url
  def http_to_file filename, url
    content = get_html_content(url)[0]
    if content
      open(filename, "wb") do |file|
        file.write(content)
      end
    end
  end

  def fetch uri_str, limit = 10
    #puts "fetching url: #{uri_str}"
    return nil if limit == 0

    url = Addressable::URI.parse(uri_str)
    url.normalize!
    #url = URI.parse(uri_str)

    req = Net::HTTP::Get.new(url.path + (url.query ? "?" + url.query : ""), {
        'User-Agent' => "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
        'Host' => url.host,
        'Connection' => 'keep-alive',
        'Cache-Control' => 'max-age=0',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding' => 'gzip,deflate,sdch',
        'Accept-Language' => 'ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4',
        'Accept-Charset' => 'windows-1251,utf-8;q=0.7,*;q=0.3',
        'Cookie' => ''
    })
    begin
      http = Net::HTTP.new(url.host, url.port)
      response = http.request(req)
      case response
        when Net::HTTPSuccess then
          enc = nil
          if response['Content-Type'].include?('charset=')
            blk1 = response['Content-Type'].split('charset=').last
            enc = blk1.split(/[ ;:\/=]/).first if blk1
          end
          [response, url.to_s, enc]
        when Net::HTTPRedirection then fetch(parse_link(response['location'], {:parsed_url => uri_str}), limit - 1)
        else
          response.error!
      end
    rescue => e
      puts "unable to fetch requested url: #{uri_str}\nerror: #{e.message}"
      #raise e
    end
  end

  def get_html_content requested_url
    response = fetch requested_url
    return ['', nil, nil] unless response

    last_url = response[1]
    encoding = response[2]
    response = response[0]

    body = response.body
    if response['Content-Encoding'] and response['Content-Encoding'].include? "gzip"
      body = Zlib::GzipReader.new(StringIO.new(body)).read
    end

    unless encoding
      doc = Nokogiri::HTML(body)
      doc.xpath('//head/meta[case_insensitive_equals(@http-equiv,\'content-type\')]', XPathFunctions.new).each do |meta|
        if meta['content'].include?('charset=')
          blk1 = meta['content'].split('charset=').last
          encoding = blk1.split(/[ ;:\/=]/).first if blk1
        end
      end
    end
    [body, last_url, encoding]
  end

  RUSSIAN_MONTHS_BASES = {"\u044F\u043D\u0432\u0430\u0440"=>1, "\u0444\u0435\u0432\u0440\u0430\u043B"=>2,
                          "\u043C\u0430\u0440\u0442"=>3, "\u0430\u043F\u0440\u0435\u043B"=>4, "\u043C\u0430"=>5,
                          "\u0438\u044E\u043D"=>6, "\u0438\u044E\u043B"=>7, "\u0430\u0432\u0433\u0443\u0441\u0442"=>8,
                          "\u0441\u0435\u043D\u0442\u044F\u0431\u0440"=>9, "\u043E\u043A\u0442\u044F\u0431\u0440"=>10,
                          "\u043D\u043E\u044F\u0431\u0440"=>11, "\u0434\u0435\u043A\u0430\u0431\u0440"=>12}

  def parse_datetime_words arg, entry = nil
    if arg
      tmp = arg.gsub(',', " ").gsub("\u0433.", "").gsub('  ', " ") #in case we add an extra space replacing a comma
      sp = tmp.split(' ')

      time_index = -1
      sp.each_index do |index|
        if sp[index].include? ':'
          time_index = index
          break
        end
      end

      date = sp[0..2]
      time = nil
      time = sp[time_index].split(':') if time_index >= 0
      if time and time.size < 3
        time << '0'
      end

      dt = datetime_rand [2012,1,1] #in case of parsing error at least generate random date
      begin
        if time
          dt = DateTime.new(date.last.to_i, RUSSIAN_MONTHS_BASES[Unicode::downcase(date[1][0..-2])], date.first.to_i, time[0].to_i, time[1].to_i, time[2].to_i)
        else
          dt = DateTime.new(date.last.to_i, RUSSIAN_MONTHS_BASES[Unicode::downcase(date[1][0..-2])], date.first.to_i)
        end
        dt = dt.strftime("%Y-%m-%d %H:%M:%S")
      rescue => e
        $stderr.puts "unable to parse date: #{arg}, error: #{e.message}"
      end
      dt
    end
  end

  def parse_date_dots arg, entry = nil
    if arg
      tmp = arg.gsub(/[^\.\d]/, "")
      dt = DateTime.strptime(tmp, "%d.%m.%Y")
      dt.strftime("%Y-%m-%d %H:%M:%S")
    end
  end

  def parse_datetime_dots_no_second arg, entry = nil
    if arg
      tmp = arg.gsub(/[^\.\d:\s]/, "")
      dt = DateTime.strptime(tmp, "%d.%m.%Y %H:%M")
      dt.strftime("%Y-%m-%d %H:%M:%S")
    end
  end

  def parse_date_slashes arg, entry = nil
    if arg
      tmp = arg.gsub(/[^\/\d]/, "")
      dt = DateTime.strptime(tmp, "%d/%m/%Y")
      dt.strftime("%Y-%m-%d %H:%M:%S")
    end
  end

  def parse_datetime_slashes_no_second arg, entry = nil
    if arg
      tmp = arg.gsub(/[^\/\d:\s]/, "")
      dt = DateTime.strptime(tmp, "%d/%m/%Y %H:%M")
      dt.strftime("%Y-%m-%d %H:%M:%S")
    end
  end

  def time_rand from = 0.0, to = Time.now
    Time.at(from + rand * (to.to_f - from.to_f))
  end

  def datetime_rand from = 0.0, to = Time.now
    if from.is_a? Array
      from = Time.local(*from)
    end
    if to.is_a? Array
      to = Time.local(*to)
    end
    t = time_rand from, to
    dt = DateTime.parse t.to_s
    dt.strftime("%Y-%m-%d %H:%M:%S")
  end

  def strip_html_tags arg, entry = nil
    if arg
      tmp = arg.gsub(/<\/?[^>]*>/m, "")
      tmp.gsub('&nbsp;', "")
    end
  end

  def parse_link arg, entry = nil
    if arg
      tmp = arg.gsub('\\', '/')
      if tmp.start_with? 'http'
        tmp
      elsif entry
        begin
          base_href = entry[:parsed_url]
          if entry[:html_data]
            doc = Nokogiri::HTML(entry[:html_data])
            base = doc.xpath('//base/@href').last
            base_href = base.content if base
          end
          URI.join(base_href, tmp).to_s
        rescue
          nil
        end
      end
    end
  end

  def generate_random_token len = 15
    o =  [('a'..'z'),('A'..'Z'),(1..9)].map{|i| i.to_a}.flatten
    (0...len).map{ o.sample }.join
  end

  def generate_filename arg, unique_token = nil
    if arg
      sp = arg.split('.')
      sp.delete_if { |val| !val or val.size <= 0 }
      if sp.size > 1
        ext = sp.last
        basename = arg[0..(-2-ext.size)]
      else
        ext = ''
        basename = sp.first
      end
      if unique_token
        "#{unique_token}_#{basename.gsub(' ', '').gsub(/\W/, '')}#{(ext.size > 0 ? ".#{ext}" : '')}"
      else
        "#{basename.gsub(' ', '').gsub(/\W/, '')}#{(ext.size > 0 ? ".#{ext}" : '')}"
      end
    end
  end

  def grab_picture arg, entry = nil, rnd_fname = false
    if arg
      arg = parse_link arg, entry
      unless arg
        puts "could not resolve image URL"
        return ""
      end

      token = nil
      if entry
        token = entry[:parsed_url]
        if token
          token = token.gsub(/https?:\/\//, '').split('/').first.gsub(/\W/, '_')
        end
      end
      if !rnd_fname
        file = generate_filename arg.split('?').first.split('/').last, token
      else
        file = "#{generate_random_token(25)}.#{arg.split('?').first.split('/').last.split('.').last}"
      end
      if entry and entry[:download_pic_path]
        filename = "#{entry[:download_pic_path]}/#{file}"
      else
        filename = "img/#{file}"
      end
      if !File.exists? filename
        begin
          http_to_file filename, arg
        rescue => err
          #$stderr.puts "unable to download picture: #{arg}\nError: #{err.message}"
          return ""
        end
      end
      "/#{filename}"
    end
  end

  def grab_picture_randomize_filename arg, entry = nil
    grab_picture arg, entry, true
  end

  def generate_short_text text, len = 200
    prev = strip_html_tags text
    if prev and prev.size > 0
      prev.strip!

      firstSpace = prev.index " ", len

      prev = prev[0, firstSpace || len]
      prev << "..."

      dd = Hpricot(prev)
      return dd.to_s.encode('utf-8', 'utf-8')
    else
      return ""
    end
  end

  def parse_css css_url, base_href, entry, root_base_html = nil
    current_url = parse_link(css_url, {:parsed_url => base_href, :html_data => root_base_html})

    ic = get_html_content(current_url)[0]
    ic.gsub!(/\s+/mi, " ")

    to_replace = []
    ic.match_all(/(?<!\@import )url\((((?<openbracket>['"])(?<src>.+?)\k<openbracket>)|(['"]{0}(?<src>[^>'"\)]+)))\)/).each do |url|
      fname = grab_picture(url[:src].strip.gsub(/['"]/, ""), {:parsed_url => current_url, :download_pic_path => entry[:download_pic_path]})
      to_replace << [url[:src], fname]
    end
    to_replace.each do |val|
      ic.gsub!(val[0], val[1])
    end

    imp_regex = /\@import ((url\((((?<ob>['"])(?<src>.+?)\k<ob>)|(['"]{0}(?<src>[^>'"\)]+)))\);?)|((?<ob>['"])(?<src>.+?)\k<ob>;?))/im
    imports = ic.match_all(imp_regex)
    imports.each do |imp|
      cc = parse_css imp[:src].strip.gsub(/['"]/, ""), current_url, entry
      ic.insert imp.begin(0), cc
    end
    ic.gsub!(imp_regex, "")

    ic.gsub!(/\/\*.*?\*\//mi, "")

    return ic
  end

  def find_block_end data, blk_start, blk_end, start = 0
    afterOpenIndex = start
    endIndex = nil
    inline_level = 0
    while true
      firstCloseIndex = data.index(blk_end, afterOpenIndex)
      firstOpenIndex = data.index(blk_start, afterOpenIndex)
      if (firstCloseIndex and !firstOpenIndex) or (firstCloseIndex and firstOpenIndex and (firstCloseIndex < firstOpenIndex))
        if inline_level < 1
          endIndex = firstCloseIndex
          break
        else
          afterOpenIndex = firstCloseIndex + data.match(blk_end, firstCloseIndex).to_s.size
          inline_level -= 1
        end
      elsif firstCloseIndex and firstOpenIndex
        afterOpenIndex = firstOpenIndex + data.match(blk_start, firstOpenIndex).to_s.size
        inline_level += 1
      else
        break
      end
    end
    endIndex
  end

  def parse_html_text arg, entry = nil
    if arg
      tmp = parse_html_text_no_css arg, entry
      if tmp =~ /<[^>]*class="[^"]*"[^>]*>/
        html = entry[:html_data]
        if html
          styles = ""
          doc = Hpricot(html)
          (doc/"style").each do |elem|
            ic = elem.inner_text
            to_replace = []
            ic.gsub!(/\s+/mi, " ")
            ic.match_all(/(?<!\@import )url\((((?<openbracket>['"])(?<src>.+?)\k<openbracket>)|(['"]{0}(?<src>[^>'"\)]+)))\)/).each do |url|
              fname = grab_picture(url[:src].strip.gsub(/['"]/, ""), entry)
              to_replace << [url[:src], fname]
            end
            to_replace.each do |val|
              ic.gsub!(val[0], val[1])
            end
            styles << ic
          end
          (doc/"link").each do |elem|
            if elem['rel'] == "stylesheet"
              styles << parse_css(elem['href'], entry[:parsed_url], entry, entry[:html_data])
            end
          end
          if styles.size > 0
            styles.gsub!(/\:\:.*?(?=[\s{,]+)/, "") #dirty workaround for handling mozilla etc extensions
            #now remove all @media tags:
            #remove any @media block except for 'screen'
            while styles.scan(/@media\s+(?!screen)\w+?\s*\{/mi).size > 0
              printIndex = styles.index(/@media\s+(?!screen)\w+?\s*\{/mi)
              if printIndex
                printCloseIndex = find_block_end styles, '{', '}', printIndex + styles.match(/@media\s+(?!screen)\w+?\s*\{/mi, printIndex).to_s.size
                if printCloseIndex
                  styles = styles[0...printIndex] + styles[printCloseIndex + 1..-1]
                end
              end
            end
            #now remove '@media screen' tags
            while styles.scan(/@media\s+screen\s*\{/mi).size > 0 #just in case some imbecile though of specifying several @screen tags
              scrIndex = styles.index(/@media\s+screen\s*\{/mi)
              scrEndIndex = find_block_end styles, '{', '}', scrIndex + styles.match(/@media\s+screen\s*\{/mi, scrIndex).to_s.size

              styles = styles[0...scrEndIndex] + styles[scrEndIndex + 1..-1]
              styles.sub!(/@media\s+screen\s*\{/mi, "")
            end
            begin
              inlined = CSS.inline(:css => styles, :body => tmp, :prune_classes => true).encode('utf-8', 'utf-8')
              tmp = inlined if inlined and inlined.size > 0
            rescue InvalidStyleException
              puts "unable to parse CSS data"
            end
          end
        end
      end
      tmp
    end
  end

  def parse_html_text_no_css arg, entry = nil
    if arg
      tmp = arg.gsub(/<script[^>]*>.*?<\/script>/im, "") #remove scripts
      tmp.gsub!(/on\w+?=(['"]{1}).*?\1/im, "") #remove all event handlers (such as onClick, onMousehover etc)
      tmp.gsub!(/<\/?a[^>]*>/im, "") #remove all anchors
      tmp.gsub!('&nbsp;', " ")

      to_replace = []

      imgs = /<img[^>]*src=(((?<openbracket>['"])(?<src>.+?)\k<openbracket>)|(['"]{0}(?<src>[^>'"\s]+)))/im
      tmp.match_all(imgs).each do |match|
        src = match[:src].strip
        pic = grab_picture src, entry
        to_replace << [src, pic]
      end

      begin
        to_replace.each do |val|
          tmp.gsub!(val[0], val[1])
        end
      rescue => err
        $stderr.puts "error while replacing img tags while parsing html\nError message:\n#{err.message}"
        return arg
      end

      tmp.strip
    end
  end

  def escape_sql_string(v)
    v.gsub(/\\/, '\&\&').gsub(/'/, "''").gsub(/(\r?\n)+/, '\n').gsub(/\r+(?!\n)/, '')
  end
end