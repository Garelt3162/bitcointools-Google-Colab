#!/usr/bin/env python3
#
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""enum-like type"""

class EnumException(Exception):
    pass

class Enumeration:
    def __init__(self, name, enum_list):
        self.__doc__ = name
        lookup = {}
        reverse_lookup = {}
        i = 0
        unique_names = []
        unique_values = []
        for x in enum_list:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumException("enum name is not a string: {}".format(x))
            if not isinstance(i, int):
                raise EnumException("enum value is not an integer: {}".format(i))
            if x in unique_names:
                raise EnumException("enum name is not unique: {}".format(x))
            if i in unique_values:
                raise EnumException("enum value is not unique for {}".format(x))
            unique_names.append(x)
            unique_values.append(i)
            lookup[x] = i
            reverse_lookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverse_lookup = reverse_lookup

    def __getattr__(self, attr):
        if attr not in self.lookup:
            raise AttributeError
        return self.lookup[attr]

    def whatis(self, value):
        return self.reverse_lookup[value]
