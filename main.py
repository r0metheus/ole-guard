#!/usr/bin/env python3

import subprocess
import scraped_pb2
import sys

encoding = 'utf-8'
def hashes(file, scraped):
	scraped.md5 = (subprocess.run(["md5sum", file], capture_output=True).stdout.split()[0]).decode(encoding)
	scraped.sha1 = (subprocess.run(["sha1sum", file], capture_output=True).stdout.split()[0]).decode(encoding)
	scraped.sha256 = (subprocess.run(["sha256sum", file], capture_output=True).stdout.split()[0]).decode(encoding)
	scraped.sha512 = (subprocess.run(["sha512sum", file], capture_output=True).stdout.split()[0]).decode(encoding)

def generic(file, scraped):
	scraped.mime = (subprocess.run(["file", "--mime-type", "-b", file], capture_output=True).stdout).decode(encoding)
	scraped.filetype = (subprocess.run(["file", file], capture_output=True).stdout).decode(encoding).strip(file)[2:]
	m = (subprocess.run(["xxd", "-l", "8",  file], capture_output=True).stdout).decode(encoding).split(':')[1].split()[:-1]
	magic = ""
	for c in m:
		magic += c+' '
	
	scraped.magic = magic
	
def strings(file, exp, scraped):
	strings = (subprocess.run(["strings", file], capture_output=True).stdout).decode(encoding).split()

	"""
	for i in range(len(strings)):
		if exp in strings[i]:
			tmp = strings[i]
	"""

	scraped.strings.extend([sub for sub in strings if exp in sub])

def oledump(file, scraped):
	scraped.oledump = (subprocess.run(["oledump.py", "-d", "--decompress", file], capture_output=True).stdout).decode(encoding)

def olevba(file, scraped):
	scraped.olevba = (subprocess.run(["olevba", file, "--decode"], capture_output=True).stdout).decode(encoding)

	min_i = max_i = 0
	for i, s in enumerate(scraped.olevba.split()):
		if '+-' in s:
			if min_i == 0:
				min_i = i
			else:
				max_i = i
	ovba = scraped.olevba.split()[min_i:max_i+1]

def main():
	filename = sys.argv[1]
	scraped = scraped_pb2.Scraped()
	hashes(filename, scraped)
	generic(filename, scraped)
	strings(filename, 'C:\\', scraped)
	oledump(filename, scraped)
	olevba(filename, scraped)

	f = open(filename+'_scraped', "wb")
	f.write(scraped.SerializeToString())
	f.close()

if __name__ == '__main__':
    main()
