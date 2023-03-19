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

if ARGV.size < 1
  puts "Wrong number of arguments"
  exit
end

sitemap = String.new(ARGV[0])
unless File.exists? sitemap
  puts "Specified file does not exist"
  exit
end

urls = []
File.open(sitemap, "r").each_line do |url|
  urls << url.strip
end

def split_url_and_add url, section
  str = url.split("/")
  if str.size > 1
    unless section.include? str[0]
      section[str[0]] = {}
    end
    split_url_and_add url.gsub("#{str[0]}/", ""), section[str[0]]
  else
    file, query = url.split("?")
    section[file] = {} unless section[file]
    section = section[file]

    if query and query.size > 0
      params = query.split("&")
      params.each do |param|
        val = param.split("=")
        section[val.first] = val.last# unless section.include? val
      end
    end
  end
end

result = {}
urls.each do |url|
  url = url.gsub(/http:\/\/[^\/]*\//, "")
  split_url_and_add url, result if url.size > 0
end

def form_html_list vals
  list = "<ul>"
  vals.each_pair do |k,v|
    list << "<li>#{k}"
    unless v.empty?
      if v.is_a? Hash
        list << form_html_list(v)
      else
        list << " = #{v}"
      end
    end
    list << "</li>"
  end
  list << "</ul>"
end

require 'pp'
pp result

File.open("./links_analyze_result.html", 'w') do |f|
  f.puts form_html_list(result)
end
