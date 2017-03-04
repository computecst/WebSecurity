#! /usr/bin/python2.7
# -*- coding: utf-8 -*-
from mod_Espartaco import MyHTMLParser
from mod_Espartaco import Analyze
from subprocess import check_output,CalledProcessError

o_analisis = Analyze("geekworld.esy.es", "80", "passwd")
my_html = o_analisis.recognition_test()
#print my_html
#result_html = str(check_output('grep a '+my_html,shell=True,universal_newlines=True))
#print(result_html)
parser = MyHTMLParser()
parser.feed(my_html)
#o_analisis.password_attack()