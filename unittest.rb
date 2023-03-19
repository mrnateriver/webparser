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

require './web_parser'

include WebParser

url = pattern 'http://www.egraphic.ru/photoshop-tutorials/text-effects/page/$0;/', (1..12)

rules = {[:full_link, flags(ParseFlags::DONT_SHIFT_SEARCH_INDEX, ParseFlags::DONT_TRIM_DATA)] => [/<div class="m_head">\s*<h3>\s*<a href="(?![^"]*viewid\.php\?lnkid)/m, '"', :parse_link],
         'pub_date' => Proc.new { datetime_rand [2012, 9, 11], [2012, 11, 10] },
         'structure_id' => 139,
         'url' => :full_link,
         'title' => ['>', '<'],
         #'test_xpath' => xpath('/html/body/div/@class="reset"', :strip_html_tags), #not implemented yet
         #'test_css' => css('h1.hht span'), #not implemented yet
         'image' => [/<img[^>]*src="(?=[^"]*"[^>]*class="post_img")/, '"', :grab_picture],
         'intro' => ['<div class="edit_block shot_post">', '<div class="technic_post">', :strip_html_tags],
         'another_intro' => ['<div class="edit_block shot_post">', closing_tag('div'), :strip_html_tags],
         ['content', [ParseFlags::DONT_OMIT_CRITERIAS]] => from(:full_link, css('div.full_story_box', :parse_html_text))}

options = {:next => Proc.new { nil },
          #:next => xpath('/body/a[@class="superlink"]/@href', :parse_link)
          #:next => [/<a[^>]*class="superlink"[^>]*href=">/, '"', :parse_link],
           :trim_data => true,
           :omit_criterias_from_result => true,
           :source_encoding => 'cp1251',
           :max_items_per_page => 40,
           :errors_dump_threshold => 30,
           :cleanup_by_fields => ['content', 'title'],
           :sql_dump_file => 'output/egraphic.sql',
           :sql_dump_table => 'article',
           :content_anchor => [/<body[^>]*>/, /<\/body>/]} #, :parse_body]}

parse from url, rules, options
