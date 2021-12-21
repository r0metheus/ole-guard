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
from nslookup import Nslookup
from urllib.parse import urlparse
from datetime import datetime
import argparse
import re
from collections import Counter

from plot import Plot

encoding = 'utf-8'
ip_reg = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

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

def check_IPv4(ip):
	return re.search(ip_reg, ip)
	
def check_domain(domain, type):
	if type == 'url':
		endpoint = urlparse(str(domain)).netloc
	else:
		if check_IPv4(domain):
			endpoint = domain

	try:
		w = whois.whois(endpoint)
		domain_name = w['domain_name']
		registrar = w['registrar']
		name_servers = w['name_servers']

	except whois.parser.PywhoisError:
		domain_name = None
		registrar = None
		name_servers = None
			
	return {'domain_name': domain_name, 'registrar': registrar, 'name_servers': name_servers}

def dns_resolver(domain, dns_query):
	ips_record = dns_query.dns_lookup(domain)

	return ips_record.answer
	
def parameters(file, timeout, fails):
	proc = subprocess.Popen(['vmonkey', file, '-o', 'tmp'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
	vmonkey_output = {}

	try:
		proc.wait(timeout=timeout)
	except subprocess.TimeoutExpired:
		fails += 1
		proc.kill()
	
	if proc.returncode == 0:
		with open('tmp', 'r') as f:
			vmonkey_output = json.load(f)
	
			f.close()
	
		res = subprocess.run(['rm', 'tmp'])
	
		return vmonkey_output
	
	else:
		fails += 1
		return {}

def logger(log):
	now = datetime.now()
	print("[{}] {}".format(now.strftime("%H:%M:%S"), log))

def main():
	
	parser = argparse.ArgumentParser(description='Just another OLE document script...')
	parser.add_argument('MLWR_DIR', metavar='MLWR_DIR', type=str, help='Where the malware(s) reside(s)')
	parser.add_argument('-v', '--vmonkey', action='store_true', help='Enable the ViperMonkey analysis')
	parser.add_argument('-t', '--timeout', type=int, default=30, help='ViperMonkey analysis timeout [default = 30s]')
	parser.add_argument('-d', '--decode', action='store_true', help='Enable olevba decode mode')
	parser.add_argument('-D', '--deobfuscate', action='store_true', help='Enable olevba deobfuscate mode')
	parser.add_argument('-c', '--checkhost', action='store_true', help='Enable check if a remote host is online')

	args = parser.parse_args()
	directory = args.MLWR_DIR
	failed_ovba = 0
	failed_vmonkey = 0

	vmonkey_timeout = args.timeout

	structure = {}

	print("""
   ____  __    ______   _____                                
  / __ \/ /   / ____/  / ___/______________ _____  ___  _____
 / / / / /   / __/     \__ \/ ___/ ___/ __ `/ __ \/ _ \/ ___/
/ /_/ / /___/ /___    ___/ / /__/ /  / /_/ / /_/ /  __/ /    
\____/_____/_____/   /____/\___/_/   \__,_/ .___/\___/_/     
                                         /_/                 
	""")

	logger("directory: {}".format(args.MLWR_DIR))
	logger("olevba: show_decoded_strings: {}, deobfuscate: {}".format(args.decode, args.deobfuscate))
	logger("vmonkey: {}, timeout: {}".format(args.vmonkey, vmonkey_timeout))

	for filename in os.listdir(directory):
		if 'artifacts' in filename:
			continue
		
		file = directory + os.path.sep + filename

		logger("Analyzing '{}'...".format(filename))
		
		vbaparser = VBA_Parser(file)

		try:
			vbaparser.analyze_macros(show_decoded_strings=args.decode, deobfuscate=args.deobfuscate)
		except:
			continue
		
		structure[filename] = {}
		structure[filename]['md5'] = md5(file)
		structure[filename]['sha1'] = sha1(file)
		structure[filename]['sha256'] = sha256(file)
		structure[filename]['sha512'] = sha512(file)
		structure[filename]['mime'] = magic.from_file(file, mime=True)

		logger("Got hashes and MIME...")

		structure[filename]['ext_endpoints'] = {}
		structure[filename]['ext_endpoints']['domains'] = {}
		structure[filename]['ext_endpoints']['IP'] = {}
		
		with open(file, 'rb') as f:
			structure[filename]['magic'] = f.read(8).hex()
		
		results = vbaparser.analysis_results

		if results is None:
			failed_ovba += 1
		
		sus = []
		iocs = []
		isProbablyDownloader = False
		isOnline = False

		logger("Now getting obfuscation methods, external endpoints infos (if any)...")

		if results is not None:
			for kw_type, keyword, description in results:
				if 'obfuscate' in description or 'VBA Stomping' in keyword:
					sus.append(keyword)
				if 'IOC' in kw_type:
					iocs.append(keyword)
					if 'http' in keyword or '://' in keyword:
						isProbablyDownloader = True
						structure[filename]['ext_endpoints']['domains'][keyword] = {}
						structure[filename]['ext_endpoints']['domains'][keyword]['whois'] = check_domain(keyword, 'url')
						if args.checkhost:
							structure[filename]['ext_endpoints']['domains'][keyword]['isOnline'] = check_host(keyword, 'url')

				if check_IPv4(keyword):
					isProbablyDownloader = True
					structure[filename]['ext_endpoints']['IP'][keyword] = {}
					structure[filename]['ext_endpoints']['IP'][keyword]['whois'] = check_domain(keyword, 'IP')
					if args.checkhost:
						structure[filename]['ext_endpoints']['IP'][keyword]['isHTTP200'] = check_host(keyword, 'IP')

		logger("Getting the hypothetical category, IOCs and number of macros...")

		structure[filename]['category'] = 'Downloader' if isProbablyDownloader else 'Dropper'
		structure[filename]['obfuscation_methods'] = list(set(sus))
		structure[filename]['iocs'] = list(set(iocs))
		structure[filename]['macros_num'] = vbaparser.nb_macros
		
		if args.vmonkey is True:
			vmonkey_out = parameters(file, vmonkey_timeout, failed_vmonkey)

			if len(vmonkey_out) != 0:
				for ioc in vmonkey_out['potential_iocs']:
					if ('http' in ioc or '://' in ioc) and ioc not in structure[filename]['ext_endpoints']['domains']:
						structure[filename]['ext_endpoints']['domains'][ioc] = {}
						structure[filename]['ext_endpoints']['domains'][ioc]['whois'] = check_domain(ioc, 'url')
						if args.checkhost:
							structure[filename]['ext_endpoints']['domains'][ioc]['isOnline'] = check_host(ioc, 'url')
					
					if check_IPv4(ioc) and ioc not in structure[filename]['ext_endpoints']['IP']:
						structure[filename]['ext_endpoints']['IP'][ioc] = {}
						structure[filename]['ext_endpoints']['IP'][ioc]['whois'] = check_domain(ioc, 'url')
						if args.checkhost:
							structure[filename]['ext_endpoints']['IP'][ioc]['isOnline'] = check_host(ioc, 'url')

			structure[filename]['vmonkey_results'] = vmonkey_out

		with open(directory+'_results.txt', 'a') as f:
			json.dump(structure[filename], f)
			f.write(os.linesep)
			f.write('\n')
		
		vbaparser.close()

	f.close()

	with open(directory+'_results.csv', 'w') as f:
		first = list(structure.keys())[0]
		cols = [col for col in structure[first]]
		
		writer = csv.DictWriter(f, fieldnames=cols)
		writer.writeheader()
		for filename in structure:
			writer.writerow(structure[filename])
		
		f.close()
	
	# TODO: modularize this 
	dns_query = Nslookup(dns_servers=["1.1.1.1"])
	malware_samples = len(structure.keys())
	domains_num = 0
	sl_domains = 0
	domains_ips = 0
	valid_whois = 0
	valid_ip_whois = 0
	ips_num = 0

	different_mime = []
	dropper = 0
	downloader = 0
	obf = []

	for key in structure.keys():
		different_mime.append(structure[key]['mime'])

		for methods in structure[key]['obfuscation_methods']:
			if len(methods) == 0:
				continue
			else:
				obf.append(methods)

		if structure[key]['category'] == 'Dropper':
			dropper += 1
		else:
			downloader += 1

		domains_num += len(structure[key]['ext_endpoints']['domains'].keys())
		ips_num += len(structure[key]['ext_endpoints']['IP'].keys())
		
		if structure[key]['ext_endpoints']['domains'] is not None:
			for domain in structure[key]['ext_endpoints']['domains']:
				ext = urlparse(domain).netloc
				if 'www.' not in ext and ext.count('.') == 2:
					sl_domains += 1
				
				if structure[key]['ext_endpoints']['domains'][domain]['whois']['domain_name'] is not None:
					valid_whois += 1
				
				ips = dns_resolver(ext, dns_query)
				domains_ips += len(ips)
		
		if structure[key]['ext_endpoints']['IP'] is not None:
			for ip in structure[key]['ext_endpoints']['IP']:
				if structure[key]['ext_endpoints']['IP'][ip]['whois']['domain_name'] is not None:
					valid_ip_whois += 1

	print("-"*32)
	print("Malware Samples: "+str(malware_samples))
	print("Number of domains: "+str(domains_num))
	print("Second-level domains: "+str(sl_domains))
	print("IPs that domains resolve to: "+str(domains_ips))
	print("Domain WHOIS records: "+str(valid_whois))
	print("IPs that malwares connect to: "+str(ips_num))
	print("IP WHOIS records: "+str(valid_ip_whois))
	print("-"*32)
	print("Different MIME: "+str(set(different_mime)))
	print("-"*32)
	print("Probably Droppers: {}; Probably Downloaders: {}".format(dropper, downloader))
	print("-"*32)
	print(str(Counter(obf)))
	print("-"*32)	
	print("DEBUG "+"-"*32)
	print("olevba failures: "+str(failed_ovba))
	print("vmonkey failures: "+str(failed_vmonkey))
	print("-"*32)
	
if __name__ == '__main__':
    main()
