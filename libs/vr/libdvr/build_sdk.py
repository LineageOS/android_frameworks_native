#!/usr/bin/python
import sys
import os
import argparse

# Run this script to generate dvr_api.h in the current directory.

def make_argument_parser():
  parser = argparse.ArgumentParser(
      description='Process DVR API headers into exportable SDK files.')
  return parser

parser = make_argument_parser()

in_file = open("include/dvr/dvr_api.h", "r")
out_file = open("./dvr_api.h", "w")

h_filename = ""
for line in in_file:
  if line.startswith("// dvr_") and line.endswith(".h\n"):
    h_filename = "include/dvr/" + line[3:].strip()
  if line.startswith("typedef ") and "(*Dvr" in line:
    start = line.find("(*Dvr") + 5
    end = line.find("Ptr)")
    if end != -1:
      name = "dvr" + line[start:end]
      # Find the comments for this function and insert into output.
      with open(h_filename, 'r') as h_file:
        h_lines = h_file.readlines()
        i = 1
        while i < len(h_lines):
          if name in h_lines[i]:
            end_i = i
            while h_lines[i - 1].startswith("//"): i -= 1
            while i < end_i:
              out_file.write(h_lines[i])
              i += 1
            break
          i += 1
  if line.startswith('#include "dvr_api_entries.h"'):
    with open("include/dvr/dvr_api_entries.h") as f:
      out_file.write(f.read())
  else:
    out_file.write(line)

in_file.close()
out_file.close()
