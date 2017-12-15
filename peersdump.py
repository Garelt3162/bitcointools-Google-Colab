#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for dumping the peers.dat in a human-readable format."""

import optparse
import os.path

from util import determine_datadir
from BCDataStream import BCDataStream

def main():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--datadir", dest="datadir", default=None,
                      help="Look for files here (defaults to bitcoin default)")
    (options, args) = parser.parse_args()

    if options.datadir is None:
        datadir = determine_datadir()
    else:
        datadir = options.datadir

    dump_peers(datadir)

def dump_peers(datadir):

    peers = BCDataStream()
    peers.clear()

    peers_file = os.path.join(datadir, "peers.dat")
    with open(peers_file, "rb") as f:
        peers.write(f.read())

    print("Network magic = {}".format(peers.read_bytes(4)))

if __name__ == '__main__':
    main()
