#!/usr/bin/env python3
import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup,Comment

parser=argparse.ArgumentParser(description="The Achilles Vulnerability analyser tool!")
parser.add_argument("-v",'--version',action='version',version='%(prog)s 1.0')
parser.add_argument("url",type=str,help="The url of HTML analyser")
parser.add_argument('--config',help="Path to config file")
parser.add_argument('-o','--output',help='Report file output path')
args=parser.parse_args()

config={'forms':True,'comments':True,'passwords':True}

if(args.config):
	print('using config file: '+args.config)
	config_file=open(args.config,'r')
	config_from_file=yaml.load(config_file)
	if(config_from_file):
		config={**config,**config_from_file}

report=''
if validators.url(args.url):
	result_html=requests.get(args.url).text
	parsed_html=BeautifulSoup(result_html,"html.parser")
	forms=(parsed_html.find_all("form"))
	comments=parsed_html.find_all(string=lambda test:isinstance(test,Comment))
	password_type=parsed_html.find_all('input',{'name':'password'})

	if(config['forms']):
		for form in forms:
			if((form.get('action').find("https")<0) and (urlparse(args.url).scheme!='https')):
				report=''+'form issue:Insecure form action '+form.get('action')+' found in document!\n'

	if(config['comments']):
		for comment in comments:
			if(comment.find('key:')>-1):
				report+='Comment issue: key is found in the HTML comments,please remove it!\n'
	
	if(config['passwords']):
		for password in password_type:
			if(password.get('type')!='password'):
				report+='Input issue: Plain text password input found, Please change password type input!\n'	
else:	
	print("Invalid Url found!")

if(report == ''):
  report='Nice job! Your HTML document is secure!'
else:
  header='Vulnerability Report is as follows:\n'
  header+='==================================\n\n'
  report=header+report

print(report)

if(args.output):
	file=open(args.output,'w')
	file.write(report)
	file.close()
	print('Report saved to: '+args.output)
