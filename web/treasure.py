
from bs4 import BeautifulSoup
import ssl
import requests

context = ssl._create_unverified_context()

URL = "http://ctf.j0n9hyun.xyz:2025/?page="
for i in range(0,3000) : 
	page = i
	URL_p = URL+str(i)
	
	html = requests.get(URL_p).text
	soup = BeautifulSoup(html,'html.parser')
	
	res = soup.find_all("p")[1].text
	if "HackCTF" in res : 
		print str(i)+" res : "+res