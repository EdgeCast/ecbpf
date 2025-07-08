#!/usr/bin/python3

import numpy
import sys

runs = []

for line in sys.stdin:
    runs.append(int(line))

bins = [0]
bins.extend([1 << i for i in range(0,18)])
hist = numpy.histogram(runs, bins=bins)

cts = hist[0]
bkts = zip(hist[1][:], hist[1][1:])
for c, b in zip(cts, bkts):
    desc = "{:>6} -> {:<6}".format(b[0], b[1])
    print("{} : {}".format(desc, c))

qs = [50,99,99.9,99.99]
ps = numpy.percentile(runs, [50,99,99.9,99.99])

print()
print("{:>7} : {:.0f}".format("Mean", numpy.mean(runs)))
for p, q in zip(ps,qs):
    desc = "P{}".format(q)
    print("{:>7} : {:.0f}".format(desc,p))
print("{:>7} : {:.0f}".format("Max", numpy.max(runs)))
