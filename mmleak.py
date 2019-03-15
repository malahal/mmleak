#!/usr/bin/env python

# This script takes a sorted mmleak.so produced dump file.  For example
# with using 'sort -s -k1,1'. It removes matching allocs and free
# records. Unmatched records are written to stdout.

import sys

def main():
    shrink(sys.stdin, sys.stdout)
    
class peek_ahead(object):
    def __init__(self, it):
        self._nit = iter(it).next
        self.preview = None
        self._step()
        self.sentinel = object()
    def __iter__(self):
        return self
    def next(self):
        result = self._step()
        if result is self.sentinel:
            raise StopIteration
        else:
            return result
    def _step(self):
        result = self.preview
        try:
            self.preview = self._nit( )
        except StopIteration:
            self.preview = self.sentinel
        return result

# allocation line with 3 fields: "pointer function size" free line with
# 2 fields: "pointer function" infile is assumed to be stable sorted
# with the first field.  Example: "sort -s -k1,1"
def shrink(infile, outfile):
    peekf = peek_ahead(infile)
    for line in peekf:
        fields = line.split()
        try:
            ptr = fields[0]
            func = fields[1]
        except:
            sys.exit("BAD line: %s" % line)

        # If this is an allocation and the next is a free with the same ptr,
        # skip this allocation and the following free.
        if len(fields) == 3:
            size = fields[2]
            pline = peekf.preview
            if pline is not peekf.sentinel:
                fields = pline.split()
                if len(fields) == 2 and ptr == fields[0]:
                    # drop this line and the matching preview free line
                    pline = peekf.next()
                    continue
        outfile.write(line)

if __name__ == "__main__":
    main()
