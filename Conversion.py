#!/usr/bin/python3
import xmltodict
import json

with open('/home/sandbox/Desktop/logs/ProcmonLog.xml', 'r') as xml_file:
        xml_data = xml_file.read()

json_data = json.dumps(xmltodict.parse(xml_data), indent=4)

with open ('/home/sandbox/Desktop/logs/ProcmonLog.json', 'w') as json_file:
	json_file.write(json_data)
