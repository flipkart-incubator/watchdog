#!/usr/bin/env python
# -*- coding: utf-8 -*-
# swf_parser for Wapiti
# Copyright (C) 2013 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

from zlib import decompress
import sys
import struct
import BeautifulSoup

# tag  7 = DefineButton
# tag 12 = DoAction
# tag 34 = DefineButton2
# tab 37 = DefineEditText
# tag 59 = DoInitAction
# tag 69 = FileAttributes
# tag 77 = Metadata
# tag 82 = DoABC


class swf_parser(object):

    __strings = []

    def __init__(self, data):
        c = data[:8]
        signature, version, file_length = struct.unpack('3scI', c)
        version = ord(version)
        data = data[8:]

        if signature == "CWS":
            data = decompress(data)
        elif signature == "FWS":
            pass  # uncompressed
        elif signature == "ZWS":
            if version < 13:
                raise Exception("Parsing error", self.__strings)
        else:
            raise Exception("Parsing error", self.__strings)

        bit_len, = struct.unpack('<B', data[:1])
        bit_len >>= 3
        reste = ((bit_len * 4) + 5) % 8
        div = ((bit_len * 4) + 5) / 8
        to_read = div - 1
        if reste:
            to_read += 1
        frame_rate, frame_count = struct.unpack('HH', data[1 + to_read: 1 + to_read + 4])
        frame_rate >>= 8
        pos = 1 + to_read + 4
        while pos < len(data):
            pos = self.read_tag(data, pos)

    def read_action_tags(self, data):
        i = 0

        while True:
            action_tag = ord(data[i])
            i += 1

            if action_tag == 0:  # action end flags
                break

            action_size = 0

            if action_tag >= 0x80:
                action_size, = struct.unpack("H", data[i: i+2])
                # The number of bytes in the ACTIONRECORDHEADER, not counting the ActionCode and Length fields.
                i += 2
            #elif action_tag in [7, 28, 0x4E, 0x4F]:
            #  continue
            else:
                continue

            if action_tag == 0x83:
                url, target = data[i:i + action_size].split("\0")[:-1]
                if url != "":
                    self.__strings.append(url)

            elif action_tag == 0x88:
                nb_strings, = struct.unpack("H", data[i: i+2])
                string_tab = data[i + 2: i + action_size].split("\0")[:-1]
                for string in string_tab:
                    if self.looksLikeAnURL(string):
                        self.__strings.append(string)

            elif action_tag == 0x96:
                values = data[i: i + action_size]
                while len(values):
                    pushed_type = ord(values[0])
                    if pushed_type in [4, 5, 8]:  # 8 bits
                        values = values[2:]
                    elif pushed_type == 9:  # 16 bits
                        values = values[3:]
                    elif pushed_type in [1, 7]:  # 32 bits
                        values = values[5:]
                    elif pushed_type == 6:  # 64 bits (float)
                        values = values[9:]
                    elif pushed_type == 0:
                        eos = values[1:].find("\0")
                        if self.looksLikeAnURL(values[1: eos+1]):
                            self.__strings.append(values[1: eos+1])
                        values = values[eos + 2:]
                    else:  # null, undefined
                        values = values[1:]

            elif action_tag == 0x9b:
                eos = data[i:i + action_size].find("\0")
                func_name = data[i:i+eos]
                nb_params, = struct.unpack("H", data[i + eos + 1: i + eos + 3])
                code_size, = struct.unpack("H", data[i + action_size - 2: i + action_size])

            # Not interesting for us: frame related etc

            elif action_tag in [0x81, 0x87, 0x8C, 0x8E, 0x99, 0x9A, 0x9D, 0x9F]:
                pass
            elif action_tag in [0x80, 0xb7, 0xD6, 0xD7, 0xF2, 0xFC]:  # Undocumented but doesn't look usefull
                pass
            elif action_tag in [0x82, 0x85, 0xDD, 0xFF]:
                # Undocumented but maybe some bytecode => regex
                pass
            else:
                #print data[i: i + action_size]
                break

            i += action_size
        return i

    def read_u30(self, data):
        i = 0
        nb = 0
        bytePos = 0
        while True:
            x = ord(data[i])
            bits = x & 127
            i += 1
            nb += bits << bytePos
            bytePos += 7
            if not x & 128:
                break
        return (nb, i)

    def read_tag(self, data, pos):
        tag, = struct.unpack('H', data[pos:pos+2])
        decal = 2
        length = tag & 63
        tag >>= 6
        if length == 63:
            length, = struct.unpack('I', data[pos+2:pos+6])
            decal += 4

        #[12, 34, 37, 59, 69, 77, 82]:
        if tag in [0, 1, 2, 4, 5, 6, 8, 9, 10, 11, 13, 14, 15, 17, 19, 20, 21, 22, 23, 24, 26, 28, 32, 33, 35, 36,
                   39, 41, 43, 45, 46, 48, 56, 60, 62, 64, 65, 66, 70, 73, 74, 75, 76, 78, 83, 84, 86, 88, 89, 90]:
            pass
        # Undocumented tags, references in https://code.google.com/p/erlswf/
        elif tag in [16, 29, 31, 38, 40, 42, 47, 49, 50, 51, 52, 63, 73]:
            pass

        if tag == 7:
            # The way is tag is formated just look damn stupid and I could not find a SWF file using it
            pass

        elif tag == 12:
            self.read_action_tags(data[pos + decal: pos + decal + length])

        if tag == 34:
            action_offset, = struct.unpack("H", data[pos + decal + 3: pos + decal + 5])
            if action_offset:
                button_cond_actions = data[pos + decal + 3 + action_offset: pos + decal + length]
                do_not_stop = 0
                i = 0
                while True:
                    do_not_stop, = struct.unpack("H", button_cond_actions[i: i + 2])
                    if i + 4 >= len(button_cond_actions):
                        break
                    i += self.read_action_tags(button_cond_actions[i + 4:])
                    if not do_not_stop:
                        break

        elif tag == 37:
            rect_bit_len = struct.unpack("<B", data[pos + decal + 2])[0] >> 3
            nb_bytes_for_rect = ((rect_bit_len * 4) + 5) / 8
            if ((rect_bit_len * 4) + 5) % 8:
                nb_bytes_for_rect += 1
            flags_start = pos + decal + 2 + nb_bytes_for_rect
            flags1, flags2 = struct.unpack("BB", data[flags_start: flags_start + 2])
            has_text = flags1 & 128
            if has_text:
                #html = flags2 & 2
                string_index = flags_start + 2
                if flags1 & 1:  # HasFont
                    string_index += 2
                if flags2 & 128:  # HasFontClass:
                    string_index += data[string_index].find("\0") + 1
                if flags1 & 1:  # HasFont
                    string_index += 2
                if flags1 & 4:  # HasTextColor:
                    string_index += 4
                if flags1 & 2:  # HasMaxLength
                    string_index += 2
                if flags2 & 16:  # HasLayout
                    string_index += 9
                text = data[string_index: pos + decal + length].split("\0")[1]
                soup = BeautifulSoup.BeautifulSoup(text)
                for link in soup.findAll("a"):
                    # BeautifullSoup doesn't work as expected with the "in" statement
                    if link.has_key("href"):
                        self.__strings.append(link["href"])

        elif tag == 59:
            self.read_action_tags(data[pos + decal + 2: pos + decal + length])

        elif tag == 82:
            name_start = pos + decal + 4
            name_len = data[name_start:].find('\0')
            minor, major = struct.unpack("HH", data[name_start + name_len + 1: name_start + name_len + 5])

            # Some loop to pass the integer arrays
            i = name_start + name_len + 5
            # Read the array of integers :
            nb, x = self.read_u30(data[i: pos + length])
            i += x
            for __ in range(nb - 1):
                z, x = self.read_u30(data[i: pos + length])
                i += x

            # Read the array of uintegers :
            nb, x = self.read_u30(data[i: pos + length])
            i += x
            for __ in range(nb - 1):
                z, x = self.read_u30(data[i: pos + length])
                i += x

            # Pass the array of doubles
            nb, x = self.read_u30(data[i: pos + length])
            i += x
            if nb > 0:
                i += (nb - 1) * 8

            # Process the array of strings
            nb, x = self.read_u30(data[i: pos + length])
            i += x
            for __ in range(nb - 1):
                nb, x = self.read_u30(data[i: pos + length])
                i += x
                string = data[i: i + nb].strip()
                if self.looksLikeAnURL(string):
                    self.__strings.append(string)
                i += nb

        decal += length
        return pos + decal

    def looksLikeAnURL(self, string):
        if string == "":
            return False
        if " " in string:
            return False
        if string.startswith("http://adobe.com/") or string.startswith("http://www.adobe.com/"):
            return False
        if string.startswith("../"):
            return True
        for ext in [".php", ".asp", ".php4", ".php5", ".html", ".xhtml",
                    ".htm", ".swf", ".xml", ".pl", ".cgi", ".rb", ".py", ".js"]:
            if ext in string and not string.startswith(ext) and not "(" in string:
                return True
        if (string.startswith("http://") or string.startswith("https://")) and len(string) > 12:
            return True
        if "?" in string and "=" in string:
            return True
        return False

    def getLinks(self):
        return self.__strings


def main():
    with open(sys.argv[1], 'rb') as fh:
        data = fh.read()
        parser = swf_parser(data)
        print("Extracted the following links : {0}".format(parser.getLinks()))


if __name__ == '__main__':
    main()
