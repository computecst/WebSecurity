#! /usr/bin/python2.7
# -*- coding: utf-8 -*-
from mod_Espartaco import Analyze
from mod_Espartaco import MyHTMLParser
import peticiones

print """		 _____     ____       ____  _      _         ___  
		| ____|___|  _ \ __ _|  _ \| |_   / \   ___ / _ \ 
		|  _| / __| |_) / _` | |_) | __| / _ \ / __| | | |
		| |___\__ \  __/ (_| |  _ <| |_ / ___ \ (__| |_| |
		|_____|___/_|   \__,_|_| \_\\__/_/   \_\___|\___/
""";

auth = input("Tipo de autenticación: 1 Basic, 2 Digest, 3 Forms ") 
protocolo = input("Protocolo: 1 HTTP, 2 HTTPS ") 
url = raw_input("URL Ej: http://geekworld.esy.es ") 
puerto = input("Puerto ")

if 0 < auth < 3 :
    peticiones.Attack(auth,int(protocolo)-1,url,puerto,"phpbb.txt.min","uhpbb.txt.min")
else:
    o_analisis = Analyze(url, puerto, "phpbb.txt")
    my_html = o_analisis.recognition_test()
    o_parser = MyHTMLParser()
    o_parser.feed(my_html)
    controller = o_parser.get_controller()
    o_analisis.password_attack(controller)
    

# ejemplo funcional
# o_analisis = Analyze("http://geekworld.esy.es", "80", "phpbb.txt")
# my_html = o_analisis.recognition_test()
# o_parser = MyHTMLParser()
# o_parser.feed(my_html)
# controller = o_parser.get_controller()
# o_analisis.password_attack(controller)
