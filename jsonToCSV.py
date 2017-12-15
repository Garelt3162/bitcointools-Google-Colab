#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reads an array of JSON objects and writes out CSV-format

Key names are in the first row.
Columns are a union of all keys in the objects."""

import csv
import json
import sys

json_string = sys.stdin.read()
json_array = json.loads(json_string)

columns = set()
for item in json_array:
    columns.update(set(item))

writer = csv.writer(sys.stdout)
writer.writerow(list(columns))
for item in json_array:
    row = []
    for c in columns:
        if c in item:
            row.append(str(item[c]))
        else:
            row.append('')
    writer.writerow(row)
