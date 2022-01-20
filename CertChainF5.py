# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from __future__ import absolute_import, division
__author__  = "Jacek Kolezynski"
__version__ = "0.0.3"
import io
import textwrap
import argparse
from datetime import datetime, timedelta
import math
import codecs
import re
import subprocess
import sys
import os
import subprocess
import pprint
try:
    from subprocess import CompletedProcess
except ImportError:
    # Python 2

    class CompletedProcess:

        def __init__(self, args, returncode, stdout=None, stderr=None):
            self.args = args
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

        def check_returncode(self):
            if self.returncode != 0:
                err = subprocess.CalledProcessError(self.returncode, self.args, output=self.stdout)
                raise err
            return self.returncode

    def sp_run(*popenargs, **kwargs):
        input = kwargs.pop("input", None)
        check = kwargs.pop("handle", False)
        if input is not None:
            if 'stdin' in kwargs:
                raise ValueError('stdin and input arguments may not both be used.')
            kwargs['stdin'] = subprocess.PIPE
        process = subprocess.Popen(*popenargs, **kwargs)
        try:
            outs, errs = process.communicate(input)
        except:
            process.kill()
            process.wait()
            raise
        returncode = process.poll()
        if check and returncode:
            raise subprocess.CalledProcessError(returncode, popenargs, output=outs)
        return CompletedProcess(popenargs, returncode, stdout=outs, stderr=errs)

    subprocess.run = sp_run
    # ^ This monkey patch allows it work on Python 2 or 3 the same way

class Cert:
    def __init__(self, subject, issuer, content, expiry=None, position = 0, missing=False):
        self.subject = subject
        self.issuer = issuer
        self.content = content
        self.expiry = expiry
        self.children = []
        self.position = position
        self.missing = missing
    
    def add_child(self, child):
        self.children.append(child)


def extract_certs_as_strings(cert_file):
    certs = []
    with io.open(cert_file) as whole_cert:
        cert_started = False
        content = ''
        for line in whole_cert:
            if '-----BEGIN CERTIFICATE-----' in line:
               if not cert_started:
                    content += line
                    cert_started = True
               else:
                    print(line)
                    print('Error, start cert found but already started')
                    sys.exit(1)
            elif '-----END CERTIFICATE-----' in line:
                if cert_started:
                    content += line
                    certs.append(content)
                    content = ''
                    cert_started = False
                else:
                    print('Error, cert end found without start')
                    sys.exit(1)
            elif cert_started:
                    content += line
        
        if cert_started:
            print('The file is corrupted')
            sys.exit(1)
    return certs


def create_certs(certs_contents):
    certs = []
    position = 1
    for content in certs_contents:
        certs.append(create_cert(content, position))
        position += 1
    return certs

def create_cert(cert_content, position):
    proc = subprocess.Popen(['openssl', 'x509', '-text'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate(cert_content.encode())
    subject = ''
    issuer = ''
    date = None
    for line in out.decode(encoding='ascii', errors='replace').split('\n'):
        match = re.match("^\s*(\w*):(.*)", line)
        if match:
            if match.group(1) == 'Subject':
                subject = match.group(2)
            elif match.group(1) == 'Issuer':
                issuer = match.group(2)
            #if match.group(3) == 'Subject':
            #    subject = match.group(4)
            #elif match.group(3) == 'Issuer':
            #    issuer = match.group(4)
        else:
            m = re.match("^\s*Not After\s?: (?P<date>.*)GMT$", line)
            if m:
                date = datetime.strptime(m.group(1).strip(), '%b %d %H:%M:%S %Y')
    return Cert(subject, issuer, cert_content, expiry=date, position=position)


def construct_tree(certs):
    roots_dir = {} # stores only root certs here
    issuers_dir = {c.subject : c for c in certs}
    for c in certs:
        if c.subject in roots_dir:
            if c.subject == c.issuer:    
                c = roots_dir[c.subject]
            # this is not self-signed cert, but was added temporarily to roots by other cert as missing parent
                c.missing = False
                del roots_dir[c.subject]   
        if c.subject == c.issuer:
            # this is self-signed cert, lets add it to roots
            roots_dir[c.issuer] = c
        else:
            # not self-signed cert
            if c.issuer in roots_dir:
                roots_dir[c.issuer].add_child(c)
            elif c.issuer in issuers_dir:
                issuers_dir[c.issuer].add_child(c)
            else:
                # this is not self signed cert, and has no parent in roots yet
                # so let's create temporary root and add it to roots
                missing_root = Cert(c.issuer, 'Unknown issuer', '', missing=True)
                roots_dir[c.issuer] = missing_root
                missing_root.add_child(c)
    return [r for r in roots_dir.values()]

def print_roots_content(roots):
    for root in roots:        
         print_cert_content(root)

def print_cert_content(root):
    now = datetime.now()
    if not root.missing and root.expiry and now < root.expiry:
        print(root.content, end='\r\n', file=sys.stderr)
    for c in root.children:
        print_cert_content(c)


def print_cert_roots(roots, position, expiry):
    printable_elements = [[],[]]
    for root in roots:
        generate_tree_elements_to_print(root, 0, printable_elements, position=position, expiry=expiry)
    
    max_first = 0
    for e in printable_elements[0]:
        max_first = max(max_first, len(e))
        if max_first > 100:
	  max_first = 100
    for e1, e2 in zip(printable_elements[0], printable_elements[1]):
        spaces = max_first - len(e1) 
        tabs = " "*spaces
	e1space = len(e1) - len(e1.lstrip())
        #e1 = textwrap.fill(e1, width=80, subsequent_indent="  ")
	e1 = e1[:100]
        #e1 = re.sub("(.{75})", "\\1\n", e1, 0, re.DOTALL)
        print (e1.encode("utf-8"), tabs.encode("utf-8"), e2.encode("utf-8"))

def generate_tree_elements_to_print(root, level, printable_elements, spaces_for_level = 4, last = False, position = False, expiry = False):
    prefix_spaces = level * spaces_for_level
    prefix = ' '*prefix_spaces
    if level == 0:
        str(prefix).encode("utf-8").decode("utf-8")
        #prefix = repr(prefix).encode('utf-8')
        prefix += '\u2501'
    else:
        if last:
            str(prefix).encode("utf-8").decode("utf-8")
            prefix += '\u2517\u2501'
        else:
            str(prefix).encode("utf-8").decode("utf-8")
            prefix += '\u2523\u2501'
    
  
    postfix = '[{}]'.format(root.position) if position and not root.missing else '' 

    postfix2 = ''
    if root.expiry:
        now = datetime.now()
        # now = datetime(2023,8,19)
        if now > root.expiry:
            postfix2 = '[EXPIRED on: {}]'.format(root.expiry)
        elif now + timedelta(days=30) > root.expiry:
            postfix2 = '[going to expire on: {}]'.format(root.expiry)
        elif expiry:
            postfix2 = '[valid until: {}]'.format(root.expiry)
    
    postfixes = postfix + ' ' + postfix2
    
    printable_elements[1].append(postfixes)
   
    presence = ' (NOT PRESENT IN THIS PEM FILE)' if root.missing else ''
    printable_elements[0].append('{} {}{}'.format(prefix, root.subject.strip(), presence))
    for i,child in enumerate(root.children):
        last = False if i < len(root.children) - 1 else True
        generate_tree_elements_to_print(child, level + 1, printable_elements, last=last, position=position, expiry=expiry)

def main():
    parser = argparse.ArgumentParser(description='View tree of certificates from pem file')
    parser.add_argument('cert_file', help='the cert file in pem format')
    parser.add_argument('-p', '--position', action='store_true', help="show position of cert in file")
    parser.add_argument('-e', '--expiry', action='store_true', help="show expiry date")
    parser.add_argument('-r', '--remove_expired', action='store_true', help="remove expired certs and output the good ones to stderr")
    parser.add_argument('-o', '--outfile', help="name of file to store good certs after remove_expired parse")    

    args = parser.parse_args()
    cert_file = args.cert_file

    # Check if the cert is in the right format
    proc = subprocess.run(['openssl', 'x509', '-noout', '-in', cert_file], stdout=None, stderr=None)
    if proc.returncode > 0:
        print('The cert must be in pem format')
        sys.exit(1)
        # TODO what about trying to convert from cer or der?
        # -> convert der to pem : openssl x509 -inform der -in cert_file.cer -out temp_out.pem

    
    certs = extract_certs_as_strings(cert_file)
    if not certs:
        print('No certs found in the pem file')
        return
    certs = create_certs(certs)
    roots = construct_tree(certs)
    print_cert_roots(roots, args.position, args.expiry)
    if args.outfile:
         fopen = open(args.outfile, 'w')
         sys.stderr = fopen
    if args.remove_expired: 
         print_roots_content(roots)
    if args.outfile:
         fopen.close()


if __name__ == '__main__':
    main()
