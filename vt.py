#!/usr/bin/env python3

'''
vt.py
Command-line utility to automatically lookup on VirusTotal all files recursively contained in a directory.

originally by Claudio Guarnieri a.k.a. botherder a.k.a. Nex on 2013-May-30
https://github.com/botherder/virustotal

modifications by Artur Mansurov a.k.a. sur a.k.a. sur98 a.k.a. sur_kg since 2020-Feb-04
https://github.com/sur98gdirc/virustotal
'''

import os
import sys
import time
import json
import requests
import hashlib
import argparse

class ConfigVirustotal:
    API_KEY = ''

    FILE_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
    FILE_REPORT_MAX_N_OBJECTS = 4

class ConfigPrint:
    TPL_SECTION = "[*] ({0}):"
    TPL_MATCH = "\t\_ Results: {0}/{1} {2}\n\t   SHA256: {3}\n\t   Scan Date: {4}"
    TPL_SIGNATURES = "\t   Signatures:\n\t\t{0}"

class XtermColor:
    @staticmethod
    def custom(text, color_code):
        if sys.platform == "win32" and os.getenv("TERM") != "xterm":
            return text

        return '\x1b[%dm%s\x1b[0m' % (color_code, text)

    @staticmethod
    def red(text):
        return XtermColor.custom(text, 31)

    @staticmethod
    def yellow(text):
        return XtermColor.custom(text, 33)

class Hash(object):
    def __init__(self, path):
        self.path = path
        self.md5 = ''
        self.sha256 = ''

    def get_chunks(self):
        fd = open(self.path, 'rb')
        while True:
            chunk = fd.read(16 * 1024)
            if not chunk:
                break

            yield chunk
        fd.close()

    def calculate(self):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        for chunk in self.get_chunks():
            md5.update(chunk)
            sha256.update(chunk)

        self.md5 = md5.hexdigest()
        self.sha256 = sha256.hexdigest()

class VirustotalAPI:
    @staticmethod
    def getReportsByHashes(hashes):
        hashes = iter(hashes)

        try:
            nextHash = next(hashes)
        except StopIteration:
            return

        while nextHash:
            count = 0
            hashesChunk = []
            while nextHash and (count < ConfigVirustotal.FILE_REPORT_MAX_N_OBJECTS):
                hashesChunk.append(nextHash)
                count += 1
                try:
                    nextHash = next(hashes)
                except StopIteration:
                    nextHash = None
            
            data = {
                'resource' : ','.join(hashesChunk),
                'apikey' : ConfigVirustotal.API_KEY
                }

            try:
                for attempt in range(10):
                    response = requests.get(ConfigVirustotal.FILE_REPORT_URL, params=data)
                    if response.status_code == 200:
                        break
                    time.sleep(10)
                else:
                    print("Virustotal service refuses to respond, run out of attempts")
                    raise Exception
                report = response.json()
            except Exception as e:
                print(XtermColor.red("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(e)))
                print('data:', repr(data))
                print('response.url:', repr(response.url))
                print('response.status_code:', response.status_code)
                print('response.headers:', repr(response.headers))
                print('response.text:', response.text)
                raise

            if type(report) is dict:
                yield report
            elif type(report) is list:
                for r in report:
                    yield r 
            else:
                print("Cant parse this report: " + repr(report))
                raise Exception
        

class Scanner(object):
    def __init__(self, path):
        self.path = path
        self.list = []

    def populate(self):
        paths = []

        if os.path.isfile(self.path):
            paths.append(self.path)
        else:
            for root, folders, files in os.walk(self.path):
                for file_name in files:
                    # Skip hidden files, might need an option for this.
                    if file_name.startswith('.'):
                        continue

                    file_path = os.path.join(root, file_name)
                    if os.path.exists(file_path):
                        paths.append(file_path)

        for path in paths:
            hashes = Hash(path)
            hashes.calculate()

            self.list.append({
                'path' : path,
                'md5' : hashes.md5,
                'sha256' : hashes.sha256
                })

    def scan(self):
        hashes = []
        for entry in self.list:
            if entry['sha256'] not in hashes:
                hashes.append(entry['sha256'])

        results = VirustotalAPI.getReportsByHashes(hashes)

        for entry in results:
            sha256 = entry['resource']

            entry_paths = []
            for item in self.list:
                if item['sha256'] == sha256:
                    if item['path'] not in entry_paths:
                        entry_paths.append(item['path'])

            print(ConfigPrint.TPL_SECTION.format('\n     '.join(entry_paths)), end=' '),

            if entry['response_code'] == 0:
                print('NOT FOUND')
            else:
                print(XtermColor.yellow('FOUND'))

                signatures = []
                for av, scan in entry['scans'].items():
                    if scan['result']:
                        signatures.append(scan['result'])
                
                if entry['positives'] > 0:
                    print(ConfigPrint.TPL_MATCH.format(
                        entry['positives'],
                        entry['total'],
                        XtermColor.red('DETECTED'),
                        entry['resource'],
                        entry['scan_date']
                        ))

                    if entry['positives'] > 0:
                        print(ConfigPrint.TPL_SIGNATURES.format('\n\t\t'.join(signatures)))

    def run(self):
        if not ConfigVirustotal.API_KEY:
            print(XtermColor.red("[!] ERROR: You didn't specify a valid VirusTotal API key.\n"))
            return

        if not os.path.exists(self.path):
            print(XtermColor.red("[!] ERROR: The target path {0} does not exist.\n".format(self.path)))
            return

        self.populate()
        self.scan()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='Path to the file or folder to lookup on VirusTotal')
    parser.add_argument('--key', type=str, action='store', default=ConfigVirustotal.API_KEY, help='VirusTotal API key')

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit()

    ConfigVirustotal.API_KEY = args.key

    scan = Scanner(args.path)
    scan.run()
