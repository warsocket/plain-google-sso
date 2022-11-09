#!/usr/bin/env python3
from os import environ
from urllib import parse
# from http.cookies import SimpleCookie
import json
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
import re

def application(environ, response):

	#Assert is POST request
	try:
		assert(environ.get("REQUEST_METHOD") == "POST")
	except AssertionError:
		response('405 Method Not Allowed', [('Content-Type', 'text/plain')])
		yield b'Only POST allowed'
		return


	#get POST body
	try:
		request_body_size = int(environ.get('CONTENT_LENGTH', 0))
	except (ValueError):
		request_body_size = 0

	request_body = environ['wsgi.input'].read(request_body_size)

	#parse POST body
	obj = parse.parse_qs(request_body)
	try:
		# clientId = obj[b'clientId'][0] # Not sent when using one tap login
		credential = obj[b'credential'][0]
		csrftoken = obj[b'g_csrf_token'][0].decode("ascii")
	except:
		response('400 Bad Request', [('Content-Type', 'text/plain')])
		yield b'Wrong POST request parameters'
		return


	# Get CSRF cookie value
	m = re.search('(^|(; ))g_csrf_token=([a-z0-9]+)', environ.get("HTTP_COOKIE"))
	if not m:
		response('400 Bad Request', [('Content-Type', 'text/plain')])
		yield b'No CSRF token in cookies'
		return

	csrfcookie = m.group(3)

	#check csrf token
	try:
		assert(csrftoken == csrfcookie)
	except AssertionError:
		response('400 Bad Request', [('Content-Type', 'text/plain')])
		yield b'CSRF token mismatch'
		return


	#Validate the token against gogle prulbic key(s)
	with open("/var/www/performAuth.json", "r") as f:
		settings = json.load(f)


	with open("/var/www/performAuth.pem.json", "r") as f:
		obj = json.load(f)


	pem_keys = list(
					map(
						lambda x: load_pem_x509_certificate(x.encode("ASCII"), default_backend()).public_key().public_bytes(Encoding.PEM, PublicFormat.PKCS1),
						obj.values()
					) 
				)
	j = None
	for key in pem_keys:
		try:
			j = jwt.decode(credential, key, audience=settings["audience"], issuer=settings["issuer"])

		except jwt.exceptions.InvalidSignatureError:
			pass

		except:
			response('401 Unauthorized', [('Content-Type', 'text/plain')])
			return

	if not j: # jwt did not mathc a single key
		response('401 Unauthorized', [('Content-Type', 'text/plain')])
		return

	#output logged in
	response('200 OK', [('Content-Type', 'text/plain')])
	yield f'Logged in as: {j["email"]}'.encode('ASCII')