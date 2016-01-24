#!/usr/bin/env python3
"""
Copyright (c) 2016 by nurupo <nurupo.contributions@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

# Gets a list of nodes from https://nodes.tox.chat/json and prints them out
# in the format of tox-bootstrapd config file.

import urllib.request
import json

response = urllib.request.urlopen('https://nodes.tox.chat/json')
raw_json = response.read().decode('ascii', 'ignore')
nodes = json.loads(raw_json)['nodes']

output = 'bootstrap_nodes = (\n'

for node in nodes:
    node_output  = '  { // ' + node['maintainer'] + '\n'
    node_output += '    public_key = "' + node['public_key'] + '"\n'
    node_output += '    port = ' + str(node['port']) + '\n'
    node_output += '    address = "'
    if len(node['ipv4']) > 4:
        output += node_output + node['ipv4'] + '"\n  },\n'
    if len(node['ipv6']) > 4:
        output += node_output + node['ipv6'] + '"\n  },\n'

# remove last comma
output = output[:-2] + '\n)\n'

print(output)
