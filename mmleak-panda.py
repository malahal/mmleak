#!/usr/bin/env python

# For using with mmleak where your final output should allocations that
# don't have any corresponding free and vice-versa. This script
# shouldn't care about frees, but better to supply only allocations!
# 
# awk 'NF==3' shrinked-dump-file | mmleak-panda.py > mmleak.html
#
# Open mmleak.html with your favorite browser and use eu-addr2line or
# other tools that convert hex to source line numbers.

import pandas as pd
import numpy as np
import sys

# columns: "addr func [size]"
fname = sys.stdin
df = pd.read_csv(fname, delim_whitespace=True, header=None, names=["addr", "func", "size"])

gr = df.groupby('func')['size'].agg(['sum', np.mean, 'count', 'min', 'max'])
df2 = gr.reset_index()

#pd.options.display.max_colwidth = 200
print("<b>Total allocation in bytes: %d </b><br>" % df2['sum'].sum())
print("<br><b>Sum sort: </b>")
df2.sort_values('sum', ascending=False).head(n=500).to_html(sys.stdout, index=False)
print("<br><b>Count sort: </b>")
df2.sort_values('count', ascending=False).head(n=500).to_html(sys.stdout, index=False)
print("<br><b>Max alloc sort: </b>")
df2.sort_values('max', ascending=False).head(n=500).to_html(sys.stdout, index=False)
