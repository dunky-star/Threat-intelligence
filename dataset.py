#%matplotlib inline
import csv
import whois
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import requests
import socket
import time
import os
import datetime
from ipwhois import IPWhois
from urllib import request
from ipwhois.utils import get_countries
import tldextract
from ipwhois.utils import get_countries

from ipwhois.experimental import bulk_lookup_rdap
from ipwhois.hr import (HR_ASN, HR_ASN_ORIGIN, HR_RDAP_COMMON, HR_RDAP, HR_WHOIS, HR_WHOIS_NIR)


countries = get_countries(is_legacy_xml=True)

# use chunk size 5
#c_size = 5

#Creating DataFrames
df = pd.read_csv('Labelled_DataSet.csv')

#Converting DomainType to numeric
mal_legit = {'malicious': 1, 'legitmate': 0}

#assign/map 0 where there is legitimate domain type and 1 where there is malicious domain type
df['DomainType'] = df['DomainType'].map(mal_legit)

def check_date_type(d):
	if type(d) is datetime.datetime:
		return d
	if type(d) is list:
		return d[0]

for index, row in df.iterrows():
	DN = df.iloc[index]['Domains']
	
	df['IPaddr'] = socket.gethostbyname(DN)
	df['IPloc'] = IPWhois(socket.gethostbyname(DN)).lookup_whois()['nets'][0]['city']
	df['DNstring'] = tldextract.extract(DN).registered_domain
	df['DNstringct'] = len(tldextract.extract(DN).registered_domain)
	df['TLD'] = tldextract.extract(DN).suffix
	df['TLDstringct'] = len(tldextract.extract(DN).suffix)
	df['ASNumber'] = IPWhois(socket.gethostbyname(DN)).lookup_whois()['asn']
	df['NetAddr'] = IPWhois(socket.gethostbyname(DN)).lookup_whois()['nets'][0]['address']
	df['NetCity'] = IPWhois(socket.gethostbyname(DN)).lookup_whois()['nets'][0]['city']
	df['NetPostCode'] = IPWhois(socket.gethostbyname(DN)).lookup_whois()['nets'][0]['postal_code']
	W = whois.whois(DN)
	df['WebsiteName'] = W.name
	df['ASRegistrar'] = W.registrar
	df['CC'] = W.country
	df['RegDate'] = check_date_type(W.creation_date)
	df['ExDate'] = check_date_type(W.expiration_date)
	df['Dstatus'] = W.status[1]

df.to_csv('data.csv', index=False, mode='a')
