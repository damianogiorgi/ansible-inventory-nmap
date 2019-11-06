#! /usr/bin/env python
"""
Usage: nmap-scan [options] <network>

Options:
    -H, --hosts                            Print *nix hosts file format [default].
    -A, --ansible                          Make Ansible inventory
    -D, --debug                            Print debug information

"""
from pysnmp.hlapi import *
import xml.etree.ElementTree as ET
from docopt import docopt
from pprint import pprint
import datetime
import os
import sys

if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
    from subprocess32 import CalledProcessError
else:
    import subprocess

out = ""

def debug(msg, obj):
    if obj is not None:
        print "DEBUG: {0} {1}\n".format(msg, pprint(obj))

def run_nmap(net):
    try:
        out = subprocess.check_output(["nmap", "-oX", "-" , "-R", "-sP" , net])
    except CalledProcessError:
        print("Error in caller\n")
        exit(1)
    return out

def parsexml(f):
  _host = {}
  tree = ET.fromstring(f)
  hosts = tree.findall('host')
  for host in hosts:
    if ET.iselement(host):
      for addr in host.findall("address"):
          _address_type = addr.get('addrtype')
          if _address_type == 'ipv4':
            _ipaddress = addr.get('addr')
            _ipaskey = _ipaddress.replace(".", "-")
            _macaddress = None
            _vendor = None
            # _host[_ipaskey] = []
          if _address_type == 'mac':
            _macaddress = addr.get('addr')
            _vendor = addr.get('vendor')
      hostname = host.find("./hostnames/hostname").get('name') if ET.iselement(host.find("./hostnames/hostname")) else _ipaskey
      # Per Host
      _host[_ipaskey] = { '_id': _ipaskey, 'name': hostname, 'ip': _ipaddress, 'mac': _macaddress, 'vendor': _vendor}
      _services = {}
      for port in host.findall("./ports/port"):
          if ET.iselement(port):
            if port.find(".//state/[@state='open']") is not None:
              #Per open Port
              state = port.find(".//state/[@state='open']")
              service = port.find('service')

              if port.get("portid") == "443":
                common_name = port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='commonName']").text \
                  if ET.iselement(port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='commonName']")) else None
                valid_after = port.find("./script/[@id='ssl-cert']/table/[@key='validity']/elem/[@key='notAfter']").text \
                  if ET.iselement(port.find("./script/[@id='ssl-cert']/table/[@key='validity']/elem/[@key='notAfter']")) else None
                orgname     = port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='organizationName']").text \
                  if ET.iselement(port.find("./script/[@id='ssl-cert']/table/[@key='subject']/elem/[@key='organizationName']")) else None
                _service = {'protocol'            :  port.get("protocol"),
                               'portid'           :  port.get("portid"),
                               'product'          :  service.get("product"),
                               'service_name'     :  service.get("name"),
                               'ssl_cn'           :  common_name,
                               'ssl_orgname'      :  orgname,
                               'ssl_valid'        :  valid_after,}
              else: 
                _service =    {'protocol'        :  port.get("protocol"),
                               'portid'           :  port.get("portid"),
                               'product'          :  service.get("product"),
                               'service_name'     :  service.get("name"),}

              if port.get("portid") not in _services.values():
                  _services.setdefault('services',[]).append(_service)


    _host[_ipaskey].update(_services)
    del _services

  if args["--debug"]:
    debug("_host Object", _host)

  return _host


def print_hosts(collection):
   for k,v in collection.iteritems():
	  print "%s\t%s" % (v['ip'],v['name'])


def print_ansible(collection):
  print "[hosts]"
  for i in collection:
    print i.replace("-",".")
    #print "%s\tansible_ssh_user=%s\tansible_ssh_pass=%s" % (i, 'root', '#password#')       

def print_raw(collection):
    pprint(collection)

if __name__ == "__main__":
   args = docopt(__doc__)
   network = args["<network>"]
   output = run_nmap(network)
   records = parsexml(output)

   if args["--hosts"]:
    print_hosts(records)   
   elif args["--ansible"]:
    print_ansible(records)
   else:
      print("Printing host records\n")
      print_hosts(records)
