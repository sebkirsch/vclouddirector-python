#!/usr/bin/python -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-
###
#
# Query vCloud Director api for organization details
#
# Author: Sebastian Kirsch
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

def GetOrgMetadata(orgId, headers):
  xmlroot = GetApiResponse('/api/admin/org/' + orgId + '/metadata', headers)

	counter = 0
	json = '{'
	for metadata in xmlroot.iter(ns + 'MetadataEntry'):
		metaval = metadata.find(ns + 'TypedValue')
		if counter > 0:
			json += ','
		json += '"' + GetXmlValue(metadata, 'Key') + '":'
		json += '"' + GetXmlValue(metaval, 'Value') + '"'
		counter = counter + 1
	json += '}'

	return json

def GetOperationLimits(orgId, headers):
	xmlroot = GetApiResponse('/api/admin/org/' + orgId, headers)

	json = '{'
	for oplimit in xmlroot.iter(ns + 'OrgOperationLimitsSettings'):
		json += '"ConsolesPerVmLimit":"' + GetXmlValue(oplimit, 'ConsolesPerVmLimit') + '",'
		json += '"OperationsPerUser":"' + GetXmlValue(oplimit, 'OperationsPerUser') + '",'
		json += '"OperationsPerOrg":"' + GetXmlValue(oplimit, 'OperationsPerOrg') + '",'
		json += '"QueuedOperationsPerUser":"' + GetXmlValue(oplimit, 'QueuedOperationsPerUser') + '",'
		json += '"QueuedOperationsPerOrg":"' + GetXmlValue(oplimit, 'QueuedOperationsPerOrg') + '"'
	json += '}'
	
	return json

def GetOrgSettings(orgId, headers):
	xmlroot = GetApiResponse('/api/admin/org/' + orgId, headers)

	json = '{'
	for setting in xmlroot.iter(ns + 'OrgGeneralSettings'):
		json += '"CanPublishCatalogs":"' + GetXmlValue(setting, 'CanPublishCatalogs') + '",'
		json += '"CanPublishExternally":"' + GetXmlValue(setting, 'CanPublishExternally') + '",'
		json += '"CanSubscribe":"' + GetXmlValue(setting, 'CanSubscribe') + '",'
		json += '"VdcQuota":"' + GetXmlValue(setting, 'VdcQuota') + '"'
	json += '}'

	return json

def JsonOutput(data):
	counter = 0

	out = '['
	for entry in data:
		if counter > 0:
			out += ','

    itemcounter = 0
		out += '{'
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

def CleanOutput(data):
	print "--------------------------------"
	print "    vCD organization details    "
	print "--------------------------------"
	for orgdata in data:
		print "Org Name:          " + orgdata['orgName']
		print "Org Display Name:  " + orgdata['displayName']
		print "Org Id:            " + orgdata['orgId']
		print "VC Folder Name:    " + orgdata['vcFolder']
		print "Org Metadata:      " + orgdata['orgMetadata']
		print "Enabled:           " + orgdata['orgEnabled']
		print "Number of VDCs:    " + orgdata['numberOfVdcs']
		print "Operation Limits:  " + orgdata['operationLimits']
		print "General Settings:  " + orgdata['generalSettings']
		print "--------------------------------"

### END FUNCTIONS ###


### MAIN ###

# Instance variables
listoforgs = []
ns = '{http://www.vmware.com/vcloud/v1.5}'
requests.packages.urllib3.disable_warnings()
args = GetArgs()

try:

	# Get Security Token
	b64auth = 'Basic ' + base64.b64encode(vcd_user + ":" + vcd_pass)
	token = GetToken(b64auth)

	# Set http headers
	headers = {'Accept' : 'application/*+xml;version=30.0', 'x-vcloud-authorization' : token}

	# Get all organizations
	xmlroot = GetApiResponse('/api/admin/orgs/query', headers)

	for orgrec in xmlroot:
		if orgrec.tag == ns + 'OrgRecord':
			orgmap = defaultdict(lambda: '')

			href = orgrec.get('href').split('/')
			orgmap['orgId'] = href[5]

			# If there is no orgId, skip this record
			if orgmap['orgId'] == '':
				continue
			else:
				orgmap['orgName'] = orgrec.get('name')
				orgmap['displayName'] =  orgrec.get('displayName')
				orgmap['numberOfVdcs'] = orgrec.get('numberOfVdcs')
				orgmap['orgEnabled'] = orgrec.get('isEnabled')
				orgmap['vcFolder'] = orgmap['orgName'] + ' (' + orgmap['orgId'] + ')'
				orgmap['orgMetadata'] = GetOrgMetadata(orgmap['orgId'], headers)
				orgmap['operationLimits'] = GetOperationLimits(orgmap['orgId'], headers)
				orgmap['generalSettings'] = GetOrgSettings(orgmap['orgId'], headers)
				listoforgs.append(orgmap)

	# Output in clean format (default)
	if not (args.quiet or args.json):
		CleanOutput(listoforgs)

	# Output in json format
	if args.json and not args.quiet:
		jsonoutput = JsonOutput(listoforgs)
		print jsonoutput

	# Exit
  sys.exit(0)

except Exception as error:
    if not args.quiet:
        print "ERROR: " + str(error)
        sys.exit(1)

#EOF
