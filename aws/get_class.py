#!/usr/bin/python
import sys
import os
import base64
import datetime
import hashlib
import hmac
import requests

### This is still work in progress -- an attempt to get the GET calls to AWS working as a Class call,
## then can pass through data via a yaml config file -- should make requesting data from aws pretty simple.



# ************* REQUEST VALUES *************

class GET_AWS(object):

  def __init__(self, method='GET', service='ec2', region='', request='', api_ver='2015-10-01'):
    self.method=method
    self.service=service
    self.host=service+'.'+region+'.amazonaws.com'
    self.endpoint='https://'+service+'.'+region+'.amazonaws.com'
    self.request = 'Action='+request+'&Version='+api_ver
    self.access = os.environ.get('AWS_ACCESS_KEY_ID')
    self.secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
      print ('No access key is available.')
      sys.exit()
    # Create a date for headers and the credential string
    self.time = datetime.datetime.utcnow()
    self.date = self.time.strftime('%Y%m%dT%H%M%SZ')
    self.datestamp = self.time.strftime('%Y%m%d') # Date w/o time, used in credential scope
    self.canonical_uri = '/'
    self.canonical_querystring = request_parameters
    self.canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
    self.signed_headers = 'host;x-amz-date'

  def sign(key, msg):
      return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

  def getSignatureKey(key, dateStamp, regionName, serviceName):
      kDate = sign(('AWS4' + key).encode('utf-8'), self.dateStamp)
      kRegion = sign(kDate, regionName)
      kService = sign(kRegion, serviceName)
      kSigning = sign(kService, 'aws4_request')
      return kSigning


  def request_url(self):

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
print 'Request URL = ' + request_url
r = requests.get(request_url, headers=headers)

print '\nRESPONSE++++++++++++++++++++++++++++++++++++'
print 'Response code: %d\n' % r.status_code
print r.text
