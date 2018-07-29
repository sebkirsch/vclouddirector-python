#!/usr/bin/python -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-
###
#
# Query vCloud Director api for all organization vdcs
#
# Author: Sebastian Kirsch <kirsch@cyberlink.ch> - Cyberlink AG
# Date:   08.07.2018
#
###
#


import sys
import json
import requests
import base64
import xml.etree.ElementTree as ET
import argparse
from collections import defaultdict


### CONFIG ###
vcd_url = 'VCD-HOSTNAME.domain.tld'
vcd_user = 'ADMINUSER@system'
vcd_pass = 'ADMIN-PASSWORD'
### END CONFIG ###


### FUNCTIONS ###
def GetArgs():
    parser = argparse.ArgumentParser(description='Query vCD api for details about all organizations')
    parser.add_argument('-j', '--json', required=False, action='store_true', help='Output data in json format')
    parser.add_argument('-s', '--save2db', required=False, action='store_true', help='Save data to mysql database')
    parser.add_argument('-q', '--quiet', required=False, action='store_true', help='Supress output')
    return parser.parse_args()

def GetToken(b64auth):
    tokenurl = 'https://' + vcd_url + '/api/sessions'
    headers = {"Accept" : "application/*+xml;version=30.0", "Authorization" : b64auth}
    response = requests.get(tokenurl, headers=headers)
    tokenval = response.headers['x-vcloud-authorization']
    return tokenval

def GetApiResponse(url, headers):
	geturl = 'https://' + vcd_url + url
	response = requests.get(geturl, headers=headers)
	xmlroot = ET.fromstring(response.text)
	return xmlroot

def GetXmlValue(xmlnode, key):
	val = xmlnode.find(ns + key)
	if val is not None and val.text is not None:
		val = val.text
	else:
		val = ''
	return val

def GetVdcMetadata(vdcId, headers):
	xmlroot = GetApiResponse('/api/admin/vdc/' + vdcId + '/metadata', headers)

    counter = 0
    metajson = '{'
	for metadata in xmlroot.iter(ns + 'MetadataEntry'):
		metaval = metadata.find(ns + 'TypedValue')
		if counter > 0:
			metajson += ','
		metajson += '"' + GetXmlValue(metadata, 'Key') + '":'
		metajson += '"' + GetXmlValue(metaval, 'Value') + '"'
		counter = counter + 1
	metajson += '}'

	return metajson

def GetRessources(xmlnode, type):
	jsonformat = ''
	
	for entry in xmlnode.iter(ns + type):
		jsonformat = '{'
		jsonformat += '"units":"' + entry.find(ns + 'Units').text + '",'
		jsonformat += '"allocated":"' + entry.find(ns + 'Allocated').text + '",'
		jsonformat += '"reserved":"' + entry.find(ns + 'Reserved').text + '",'
		jsonformat += '"limit":"' + entry.find(ns + 'Limit').text + '"'
		jsonformat += '}'

	return jsonformat

def GetStorageProfiles(xmlnode, headers):
	counter = 0

	storprofile = '['
	for profile in xmlnode.iter(ns + 'VdcStorageProfile'):
		name = profile.get('name')
		href = profile.get('href').split('/')
		id = href[6]

		xmlroot = GetApiResponse('/api/admin/vdcStorageProfile/' + id, headers)

		for storprof in xmlroot.iter(ns + 'AdminVdcStorageProfile'):
			
			if counter > 0:
				storprofile += ','
			storprofile += '{'
			storprofile += '"spName":"' + name + '",'
			storprofile += '"spId":"' + id + '",'
			storprofile += '"Units":"' + GetXmlValue(storprof, 'Units') + '",'
			storprofile += '"Limit":"' + GetXmlValue(storprof, 'Limit') + '",'
			storprofile += '"Enabled":"' + GetXmlValue(storprof, 'Enabled') + '",'
			storprofile += '"Default":"' + GetXmlValue(storprof, 'Default') + '"'
			storprofile += '}'

		counter = counter + 1
	storprofile += ']'

	return storprofile

def GetOrgVdcs(orgId, headers):
	listoforgvdc = []

	xmlroot = GetApiResponse('/api/admin/org/' + orgId, headers)

	for vdcrec in xmlroot.iter(ns + 'Vdc'):

		vdcmap = defaultdict(lambda: '')
		vdcmap['orgId'] = orgId
		href = vdcrec.get('href').split('/')
		vdcmap['vdcId'] = href[6]
		vdcmap['vdcName'] = vdcrec.get('name')

		if vdcmap['vdcName'] and vdcmap['vdcId']:
			vdcmap['vcRPname'] = vdcmap['vdcName'] + ' (' + vdcmap['vdcId'] + ')'

			xmlroot = GetApiResponse('/api/admin/vdc/' + vdcmap['vdcId'], headers)

			for vdc in xmlroot.iter(ns + 'AdminVdc'):
				vdcmap['vdcEnabled'] = GetXmlValue(vdc, 'IsEnabled')
				vdcmap['vdcNicQuota'] = GetXmlValue(vdc, 'NicQuota')
				vdcmap['vdcNetQuota'] = GetXmlValue(vdc, 'NetworkQuota')
				vdcmap['vdcVmQuota'] = GetXmlValue(vdc, 'VmQuota')
				vdcmap['vdcCpuMhz'] = GetXmlValue(vdc, 'VCpuInMhz')
				vdcmap['vdcMemGuarantee'] = GetXmlValue(vdc, 'ResourceGuaranteedMemory')
				vdcmap['vdcCpuGuarantee'] = GetXmlValue(vdc, 'ResourceGuaranteedCpu')
				vdcmap['vdcThinProv'] = GetXmlValue(vdc, 'IsThinProvision')
				vdcmap['vdcFastProv'] = GetXmlValue(vdc, 'UsesFastProvisioning')

				for rpref in vdc.iter('{http://www.vmware.com/vcloud/extension/v1.5}MoRef'):
					vdcmap['vcRPref'] = rpref.text

				vdcmap['vdcMetadata'] = GetVdcMetadata(vdcmap['vdcId'], headers)

				vdcmap['vdcStorProfiles'] = GetStorageProfiles(vdc, headers)
				vdcmap['vdcCpuRessources'] = GetRessources(vdc, 'Cpu')
				vdcmap['vdcMemRessources'] = GetRessources(vdc, 'Memory')

			listoforgvdc.append(vdcmap)

	return listoforgvdc

def JsonOutput(data):
	counter = 0

	out = '['
	for entry in data:
		if counter > 0:
			out += ','
		out += '{'
		itemcounter = 0
		for key,value in entry.items():
			if itemcounter > 0:
				out += ','
			if value[:1] == '[' or value[:1] == '{':
				out += '"' + key + '":' + value
			else:
				out += '"' + key + '":"' + value + '"'
			itemcounter = itemcounter + 1
		out += '}'
		counter = counter + 1
	out += ']'
	return out

def CleanOutput(vdcs):
	print "--------------------------------"
	print "     vCD organization VDCs      "
	print "--------------------------------"
	for vdc in vdcs:
		print "VDC Name:           " + vdc['vdcName']
		print "VDC Id:             " + vdc['vdcId']
		print "VDC Enabled:        " + vdc['vdcEnabled']
		print "VDC Metadata:       " + vdc['vdcMetadata']
		print "Org Id:             " + vdc['orgId']
		print "VC ResPool Name:    " + vdc['vcRPname']
		print "VC ResPool MoRef:   " + vdc['vcRPref']
		print "VM Quota:           " + vdc['vdcVmQuota']
		print "NIC Quota:          " + vdc['vdcNicQuota']
		print "Network Quota:      " + vdc['vdcNetQuota']
		print "vCPU MHz:           " + vdc['vdcCpuMhz']
		print "Guaranteed Memory:  " + vdc['vdcMemGuarantee']
		print "Guaranteed CPU:     " + vdc['vdcCpuGuarantee']
		print "CPU Ressources:     " + vdc['vdcCpuRessources']
		print "Memory Ressources:  " + vdc['vdcMemRessources']
		print "Storage Profiles:   " + vdc['vdcStorProfiles']
		print "Thin Provisioning:  " + vdc['vdcThinProv']
		print "Fast Provisioning:  " + vdc['vdcFastProv']
		print "--------------------------------"

### END FUNCTIONS ###


### MAIN ###

# Instance variables 
listofvdc = []
ns = '{http://www.vmware.com/vcloud/v1.5}'
requests.packages.urllib3.disable_warnings()
args = GetArgs()

try:

    # Get Security Token
    b64auth = 'Basic ' + base64.b64encode(vcd_user + ":" + vcd_pass)
    token = GetToken(b64auth)

    # Set http headers
    headers = {'Accept' : 'application/*+xml;version=30.0', 'x-vcloud-authorization' : token}

    # Get organizations
	xmlroot = GetApiResponse('/api/admin/orgs/query', headers)

    for orgrec in xmlroot:
		if orgrec.tag == ns + 'OrgRecord':
			orgvdc = []
            orgId = ''

			href = orgrec.get('href').split('/')
			orgId = href[5]

			# If there is no orgId, skip this record
            if orgId == '':
                continue
            else:
				# Get all vdcs for this org
				orgvdc = GetOrgVdcs(orgId,headers)

				# Check if there are any vdc for this org and append it to thel global listofvdc
				if orgvdc:
					for vdc in orgvdc:
		                listofvdc.append(vdc)

						
	# Output in clean format (default)
	if not (args.quiet or args.json):
		CleanOutput(listofvdc)


	# Output in json format
	if args.json and not args.quiet:
		jsonoutput = JsonOutput(listofvdc)
		print jsonoutput

    # Exit
    sys.exit(0)

except Exception as error:
    if not args.quiet:
        print "ERROR: " + str(error)
        sys.exit(1)

#EOF
