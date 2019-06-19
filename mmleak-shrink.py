#!/usr/bin/env python

# This script takes a dump file produced my mmleak.so (as stdin).  It
# removes the matching alloc and free records.  Unmatched records are
# written to stdout.

import sys

def main():
    shrink(sys.stdin, sys.stdout)
    
def shrink(inf, outf):
    adict = {} # allocation dict
    fdict = {} # free dict
    for line in inf:
        alloc = False
        fields = line.split()
        try:
            ptr = fields[0]
            func = fields[1]
            if len(fields) == 3:
                alloc = True
                size = fields[2]
        except:
            sys.exit("BAD line: %s" % line)

        if alloc:
            if ptr in adict:
                sys.exit("twice allocated: %s %s %s" % (ptr, func, size))
            adict[ptr] = (func, size)
        else:
            if ptr in adict:
                del adict[ptr]
            else:
                if ptr in fdict:
                    sys.exit("twice freed: %s %s" % (ptr, func))
                fdict[ptr] = func

    # Write out free dict first, and then allocation dict */
    for ptr in fdict:
        outf.write("%s %s\n" % (ptr, fdict[ptr]))

    for ptr in adict:
        outf.write("%s %s %s\n" % (ptr, adict[ptr][0], adict[ptr][1]))

if __name__ == "__main__":
    main()
