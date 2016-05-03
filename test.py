#!/usr/bin/python
# AWS Version 4 signing example

# EC2 API (DescribeRegions)

# See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
# This version makes a GET request and passes the signature
# in the Authorization header.
import sys, os, base64, datetime, hashlib, hmac, re, string
import requests # pip install requests
#from xml.etree import ElementTree
#import xml.etree.cElementTree as etree
from xmljson import yahoo as xj_out
from xml.etree.ElementTree import fromstring
from pprint import pprint
from json import dumps

# ************* REQUEST VALUES *************
method = 'GET'
service = 'ec2'
region = 'eu-west-1'
host = 'ec2.'+region+'.amazonaws.com'
#<regionEndpoint>ec2.eu-west-1.amazonaws.com</regionEndpoint>
#<#regionName>eu-west-1</regionName>
endpoint = 'https://ec2.'+region+'.amazonaws.com'
#request_parameters = 'Action=DescribeRegions&Version=2013-10-15'
request_parameters = 'Action=DescribeVpcs&Version=2015-10-01'

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

# Read AWS access key from env. variables or configuration file. Best practice is NOT
# to embed credentials in code.
access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
if access_key is None or secret_key is None:
    print 'No access key is available.'
    sys.exit()

# Create a date for headers and the credential string
t = datetime.datetime.utcnow()
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope


# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

# Step 1 is to define the verb (GET, POST, etc.)--already done.

# Step 2: Create canonical URI--the part of the URI from domain to query
# string (use '/' if no path)
canonical_uri = '/'

# Step 3: Create the canonical query string. In this example (a GET request),
# request parameters are in the query string. Query string values must
# be URL-encoded (space=%20). The parameters must be sorted by name.
# For this example, the query string is pre-formatted in the request_parameters variable.
canonical_querystring = request_parameters

# Step 4: Create the canonical headers and signed headers. Header names
# and value must be trimmed and lowercase, and sorted in ASCII order.
# Note that there is a trailing \n.
canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'

# Step 5: Create the list of signed headers. This lists the headers
# in the canonical_headers list, delimited with ";" and in alpha order.
# Note: The request can include any headers; canonical_headers and
# signed_headers lists those that you want to be included in the
# hash of the request. "Host" and "x-amz-date" are always required.
signed_headers = 'host;x-amz-date'

# Step 6: Create payload hash (hash of the request body content). For GET
# requests, the payload is an empty string ("").
payload_hash = hashlib.sha256('').hexdigest()

# Step 7: Combine elements to create create canonical request
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash


# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, either SHA-1 or
# SHA-256 (recommended)
algorithm = 'AWS4-HMAC-SHA256'
credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()


# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the function defined above.
signing_key = getSignatureKey(secret_key, datestamp, region, service)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()


# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# The signing information can be either in a query string value or in
# a header named Authorization. This code shows how to use a header.
# Create authorization header and add to request headers
authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

# The request can include any headers, but MUST include "host", "x-amz-date",
# and (for this scenario) "Authorization". "host" and "x-amz-date" must
# be included in the canonical_headers and signed_headers, as noted
# earlier. Order here is not significant.
# Python note: The 'host' header is added automatically by the Python 'requests' library.
headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}


# ************* SEND THE REQUEST *************
request_url = endpoint + '?' + canonical_querystring

print '\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++'
#print 'Request URL = ' + request_url
r = requests.get(request_url, headers=headers, stream=True)
#r = requests.get(request_url, headers=headers)
r.raw.decode_content = True

#print r.text
#print r.content

xml_raw = []
for line in r.iter_lines():
  if re.search(r'<DescribeVpcsResponse',line):
    '''#print(line)'''
    xml_raw.append('<DescribeResponse xmlns="">')
  elif re.search(r'</DescribeVpcsResponse',line):
    '''#print(line)'''
    xml_raw.append('</DescribeResponse>')
  else:
    xml_raw.append(line)

xr_string=string.join(xml_raw, "\n")


raw_data = xj_out.data(fromstring(xr_string))
#raw_data = dumps(xj_out.data(fromstring(xr_string)))

#print r.content
print ("raw_data ==", raw_data)
#print ("raw_json ==", raw_json)
#xj_data = raw_data["DescribeResponse"]

xj_data = raw_data
for key0 in xj_data:
  print "key0 ==", key0
  ##print "data ==", xj_data[key0]
  #if re.search(r'vpcSet', key0):
  #  for key1 in xj_data[key0]['item']:
  #    print "key1 == ", key1
  #    #print "key1 == ", key1
  #    print "data == ", xj_data[key0][key1]

#      for next_1 in raw_data[item][key]:
#        print "next_1 == ", next_1, key
#        #print "data ==", raw_data[item][key][next_1]
#        for next_2 in raw_data[item][key][next_1]:
#          print "next_2 == ", next_2
#        #if re.search(r'cidrBlock', next_1):


print '\nRESPONSE++++++++++++++++++++++++++++++++++++'
print 'Response code: %d\n' % r.status_code
  #print ("tree == ")
#pprint(tree)
  #pprint(event)
