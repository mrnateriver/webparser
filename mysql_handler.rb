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

require 'mysql2'

class MysqlResultsHandler
  #@client
  #@data_table
  #@conv_encoding
  attr_accessor :data_table
  attr_accessor :conv_encoding
  attr_accessor :dump_file

  def initialize connect_info
    raise ArgumentException unless connect_info.class == Hash
    @client = Mysql2::Client.new connect_info
    @data_table = connect_info[:data_table] || 'data'
    @conv_encoding = connect_info[:conv_encoding] || nil
    @dump_file = nil
  end

  def process data
    return nil unless data.is_a? Array

    if @dump_file
      File.open(@dump_file, 'w') do |f|
        data.each do |row|
          query = "INSERT INTO #{@data_table} ("
          values = ""
          row.each do |key, value|
            next if key.is_a? Symbol

            query << '`' << key.to_s << '`,'

            val = value.to_s
            if @conv_encoding
              val.encode! 'utf-8', @conv_encoding
            end
            #val.encode! 'utf-8'
            values << '\'' << @client.escape(val) << '\','
          end
          query.chomp! ','
          values.chomp! ','

          query << ") VALUES (" << values << ");"
          #@client.query query
          f.puts query
        end
      end
    else
      data.each do |row|
        query = "INSERT INTO #{@data_table} ("
        values = ""
        row.each do |key, value|
          next if key.is_a? Symbol

          query << '`' << key.to_s << '`,'

          val = value.to_s
          if @conv_encoding
            val.encode! 'utf-8', @conv_encoding
          end
          #val.encode! 'utf-8'
          values << '\'' << @client.escape(val) << '\','
        end
        query.chomp! ','
        values.chomp! ','

        query << ") VALUES (" << values << ");"
        @client.query query
        #f.puts query
      end
    end
  end
end
