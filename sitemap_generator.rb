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

if ARGV.size < 2
  puts "Wrong number of arguments"
  exit
end

sitemap = String.new(ARGV[0])
unless File.exists? sitemap
  puts "Specified file does not exist"
  exit
end

$domain = String.new(ARGV[1])
unless $domain.start_with? "http://"
  puts "Wrong domain specified"
end
begin
  URI.parse $domain
rescue
  puts "Wrong domain specified"
end

def process_single_result data, startCriteria, endCriteria
  return nil unless data.is_a? String
  result = nil
  if (startCriteria.is_a?(String) or startCriteria.is_a?(Regexp)) and (endCriteria.is_a?(String) or endCriteria.is_a?(Regexp))
    openIndex = data.index(startCriteria, 0)
    #check if we found the data
    if openIndex
      if startCriteria.is_a? Regexp
        openIndex += data.match(startCriteria, 0).to_s.size
      else
        openIndex += startCriteria.size
      end

      lastIndex = data.index(endCriteria, openIndex)
      if lastIndex
        cut = data.slice(openIndex..lastIndex-1)
        cut.strip!
        result = cut
      else
        $stderr.puts "couldn't find data end for single result with criteria: #{endCriteria}"
      end
    else
      $stderr.puts "couldn't find data start for single result with criteria: #{startCriteria}"
    end
  else
    $stderr.puts "wrong type of arguments provided for processing single result: criterias should be strings or regexps"
  end
  result
end

urls = []
File.open(sitemap, "r").each_line do |url|
  urls << url.strip
end

def split_url_and_add url, section
  str = url.split("/")
  unless section.include? str[0]
    section[str[0]] = {}
  end
  if str.size > 1
    split_url_and_add url.gsub("#{str[0]}/", ""), section[str[0]]
  end
end

result = {}
urls.each do |url|
  url = url.gsub($domain, "")
  split_url_and_add url, result if url.size > 0
end

def form_html_list vals, prev = nil
  list = "<ul>"
  vals.each_pair do |k,v|
    url = String.new($domain)
    if prev
      url << prev
    end
    url << k

    puts url
    data = open(url)
    if data.content_encoding == ["gzip"]
      data = Zlib::GzipReader.new(data).read
    else
      data = data.read
    end
    data.encode! 'utf-8', 'utf-8', :invalid => :replace, :undef => :replace, :replace => ' '

    title = process_single_result data, "<title>", "</title>"

    list << "<li><a href=\"#{url}\">#{k}</a>"
    unless v.empty?
      list << form_html_list(v, "#{prev.to_s}#{k}/")
    end
    list << "</li>"
  end
  list << "</ul>"
end

#require 'pp'
#pp result

File.open("./sitemap_output.html", 'w') do |f|
  f.puts form_html_list(result)
end
