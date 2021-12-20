#!/usr/bin/env python3

from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML, SUSPICIOUS_KEYWORDS, detect_patterns
import hashlib
import subprocess
import sys
import os
import magic
import json
import requests, json
import whois
import csv

encoding = 'utf-8'

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

def check_host(endpoint, type):
	headers = {'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36'}
	if type == 'url':
		url = 'https://check-host.net/check-http?host='+endpoint+'&max_nodes=3'
		res = requests.get(url, headers=headers).json()
		url = 'https://check-host.net/check-result/'+res['request_id']
		res = requests.get(url, headers=headers).json()
		
		for record in res.keys():
			if res[record] is None:
				continue
			if 'OK' in res[record][0] or '200' in res[record][0]:
				return True
		return False

	if type == 'IP':
		res = subprocess.run(['ping', endpoint, '-c', '2'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
		if res.returncode == 0:
			return True
		return False	
	
def check_domain(domain):
	endpoint = domain.strip('http://').split('/')[0]

	w = whois.whois(endpoint)

	domain_name = w['domain_name']
	registrar = w['registrar']
	name_servers = w['name_servers']

	return {'domain_name': domain_name, 'registrar': registrar, 'name_servers': name_servers}
	
def parameters(file, timeout):
	proc = subprocess.Popen(['vmonkey', file, '-o', 'tmp'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
	vmonkey_output = {}

	try:
		proc.wait(timeout=timeout)
	except subprocess.TimeoutExpired:
		proc.kill()
	
	if proc.returncode == 0:
		with open('tmp', 'r') as f:
			vmonkey_output = json.load(f)
	
			f.close()
	
		res = subprocess.run(['rm', 'tmp'])
	
	return vmonkey_output

def main():
	enableWhois = True
	directory = sys.argv[1]
	structure = {}

	for filename in os.listdir(directory):
		if 'artifacts' in filename:
			continue

		file = directory + os.path.sep + filename
		vbaparser = VBA_Parser(file)
		
		structure[filename] = {}
		structure[filename]['md5'] = md5(file)
		structure[filename]['sha1'] = sha1(file)
		structure[filename]['sha256'] = sha256(file)
		structure[filename]['sha512'] = sha512(file)
		structure[filename]['mime'] = magic.from_file(file, mime=True)
		structure[filename]['ext_endpoints'] = {}
		structure[filename]['ext_endpoints']['domains'] = {}
		structure[filename]['ext_endpoints']['IP'] = {}
		
		with open(file, 'rb') as f:
			structure[filename]['magic'] = f.read(8).hex()

		vbaparser.analyze_macros(show_decoded_strings=False, deobfuscate=False)
		results = vbaparser.analysis_results

		sus = []
		iocs = []
		isProbablyDownloader = False
		isOnline = False

		for kw_type, keyword, description in results:
			if 'obfuscate' in description or 'VBA Stomping' in keyword:
				sus.append(keyword)
			if 'IOC' in kw_type:
				iocs.append(keyword)
				if 'http' in keyword:
					isProbablyDownloader = True
					structure[filename]['ext_endpoints']['domains'][keyword] = {}
					structure[filename]['ext_endpoints']['domains'][keyword]['whois'] = {}
					structure[filename]['ext_endpoints']['domains'][keyword]['isOnline'] = check_host(keyword, 'url')
					structure[filename]['ext_endpoints']['domains'][keyword]['whois'] = str(check_domain(keyword))

			if 'IP' in description:
				isProbablyDownloader = True
				structure[filename]['ext_endpoints']['IP'][keyword] = {}
				structure[filename]['ext_endpoints']['IP'][keyword]['whois'] = {}
				structure[filename]['ext_endpoints']['IP'][keyword]['isHTTP200'] = check_host(keyword, 'IP')
				structure[filename]['ext_endpoints']['IP'][keyword]['whois'] = str(check_domain(keyword))

		structure[filename]['category'] = 'Downloader' if isProbablyDownloader else 'Dropper'
		structure[filename]['obfuscation_methods'] = list(set(sus))
		structure[filename]['iocs'] = list(set(iocs))
		structure[filename]['macros_num'] = vbaparser.nb_macros
		structure[filename]['vmonkey_results'] = parameters(file, 30)
		
		with open(directory+'_results.txt', 'a') as f:
			json.dump(structure[filename], f)
			f.write(os.linesep)
			f.write('\n')
		
		vbaparser.close()

	f.close()

	with open(directory+'_results.csv', 'w') as f:
		first = list(structure.keys())[0]
		cols = [col for col in structure[first]]
		print(cols)
		
		writer = csv.DictWriter(f, fieldnames=cols)
		writer.writeheader()
		for filename in structure:
			writer.writerow(structure[filename])
		
		f.close()


if __name__ == '__main__':
    main()
