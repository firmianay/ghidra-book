# Counts the number of defined strings that match a regex in the current
# selection, or current program if no selection is made, and displays the
# results on the console
#@author Ghidrabook
#@category Ghidrabook.CH14
#@keybinding 
#@menupath 
#@toolbar
#
# Copyright (c) 2019 Kara Nance (knance@securityworks.com)
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of 
# this software and associated documentation files (the "Software"), to deal in 
# the Software without restriction, including without limitation the rights to 
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of 
# the Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import re

regex = askString(
    "RegEx", "Please enter the regex you're looking to match:")

listing = currentProgram.getListing()

if currentSelection != None:
    dataIt = listing.getDefinedData(currentSelection, True)
else:
    dataIt = listing.getDefinedData(True)

counter = 0;
while dataIt.hasNext() and not monitor.isCancelled():
    data = dataIt.next()
    data_type = data.getDataType().getName().lower()
    if 'unicode' in data_type or 'string' in data_type:
        s = data.getDefaultValueRepresentation()
        if re.match(regex, s) is not None:
            counter+=1
            print(s)

print('%d matching strings were found' % (counter, ))