import requests
from bs4 import BeautifulSoup
import os
import pprint
import sys

inp = str(sys.argv[1])
f = open(inp)

soup = BeautifulSoup(f.read(),"lxml")
table = soup.find_all("div",{"id":"\\\"issue_types\\\""})

table = BeautifulSoup(str(table),"lxml")
data = table.find_all("table")

categories = []

catFile = open("categories.txt")
catFile = catFile.read()


requiredCategories = catFile.split("\n")
finalCount = 0

for issue in table:
	issue = BeautifulSoup(str(issue),"lxml")
	datasList = issue.find_all("td")
	# print len(datas)
	for datas in datasList:
		try:
			tr = BeautifulSoup(str(datas),"lxml")
			name = tr.find_all("span")[0]
			count = tr.find_all("span")[1]
			Name = name.string
			Count = count.string.split("(")[1].split(")")[0]
			categories.append({"name":Name,"count":Count})
		except:
			pass

for i in categories:
	for j in requiredCategories:
		if(i["name"]==j):
			finalCount += int(i["count"])

print finalCount
