#!/usr/bin/env python3

from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
import hashlib
import subprocess
import sys
import os
import magic
import json

encoding = 'latin-1'

def md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def sha1(filename):
    hash_sha1 = hashlib.sha1()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def sha256(filename):
    hash_sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def sha512(filename):
    hash_sha512 = hashlib.sha512()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha512.update(chunk)
    return hash_sha512.hexdigest()

def generic(file, scraped):
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

def main():
	directory = sys.argv[1]
	structure = {}

	for filename in os.listdir(directory):
		file = directory + os.path.sep + filename
		vbaparser = VBA_Parser(file)
		
		structure[filename] = {}
		structure[filename]['md5'] = md5(file)
		structure[filename]['sha1'] = sha1(file)
		structure[filename]['sha256'] = sha256(file)
		structure[filename]['sha512'] = sha512(file)
		structure[filename]['mime'] = magic.from_file(file, mime=True)
		
		with open(file, 'rb') as f:
			structure[filename]['magic'] = f.read(8).hex()

		vbaparser.analyze_macros(show_decoded_strings=False, deobfuscate=False)
		results = vbaparser.analysis_results

		sus = []
		for kw_type, keyword, description in results:
			if 'to obf' in description:
				sus.append(keyword)

		structure[filename]['obfuscation_methods'] = list(set(sus))
		structure[filename]['macros_num'] = vbaparser.nb_macros()

		with open(directory+'_results', 'a') as f:
			json.dump(structure[filename], f)
			f.write(os.linesep)

	f.close()

if __name__ == '__main__':
    main()
