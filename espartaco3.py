#! /usr/bin/python2.7
# -*- coding: utf-8 -*-
from mod_Espartaco import Analyze
from mod_Espartaco import MyHTMLParser

o_analisis = Analyze("geekworld.esy.es", "80", "phpbb.txt")
my_html = o_analisis.recognition_test()
o_parser = MyHTMLParser()
o_parser.feed(my_html)
controller = o_parser.get_controller()
o_analisis.password_attack(controller)