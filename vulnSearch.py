import requests, csv, io, json
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)
SEARCHTIME = NOW - timedelta(days=3)
NOW = NOW.isoformat(timespec="milliseconds").replace("+00:00","Z")
SEARCHTIME = SEARCHTIME.isoformat(timespec="milliseconds").replace("+00:00","Z")

class VulnerabilityClient:
	def __init__(self):
		self.session = requests.Session()
		self.headers = {"Accept":"application/json"}
		self.vulnList = []

	def get_nvd(self):
		url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
		params = {
		    "cvssV3Metrics": "AV:N/AC:L/PR:N/UI:N",
		    "resultsPerPage": 10,
		    "pubStartDate": SEARCHTIME,
		    "pubEndDate": NOW
		}
		response = self.session.get(url, headers=self.headers, params=params)
		data = response.json()
		return data

	def get_gad(self):
		url = "https://api.github.com/graphql"
		headers = self.headers.copy()
		apikey = ""
		headers['Authorization'] = f"Bearer {apikey}"

		query = '''
		{
			securityVulnerabilities(first:10, severities:[HIGH, CRITICAL]) {
				nodes {
					advisory {
						summary,
						severity,
						updatedAt,
						cvss {
							score,
							vectorString
						},
						identifiers {
						type,
						value
						}
					},
					package {
						name,
						ecosystem
					}
				}
			}
		}
		'''

		response = self.session.post(url, headers=headers, json={"query":query})
		return response.json()

	def get_euvd(self):
		url = "https://euvdservices.enisa.europa.eu/api/search?fromScore=7&toScore=10"
		response = self.session.get(url, headers=self.headers)
		data = response.json()
		return data

	def findKeys(self, data, keys, vulnObject=None):
		if vulnObject is None:
			vulnObject = {}
		for key in keys[:]:
			if isinstance(data, dict):
				for k, v in data.items():
					if k == key:
						vulnObject[k] = v
						keys.remove(key)
					self.findKeys(v, keys, vulnObject)

			elif isinstance(data, list):
				for item in data:
					self.findKeys(item, keys, vulnObject)

		return vulnObject

	def updateList(self, vulnObject):
		valueExist = any(item.get("id") == vulnObject.get("id") for item in self.vulnList)
		if not valueExist:
			self.vulnList.append(vulnObject)

	def getList(self):
		return self.vulnList



	def filterListByMetrics(self):
		filteredList = []
		for vuln in self.vulnList:
			if not vuln.get("vectorString") is None:
				metrics = vuln.get("vectorString").split("/")
				parsed_metrics = {}
				for metric in metrics:
					k, v = metric.split(":")
					parsed_metrics[k] = v

				if parsed_metrics.get("AV") == "N" and parsed_metrics.get("AC") == "L" and (parsed_metrics.get("PR") == "N" or parsed_metrics.get("PR") == "L") and parsed_metrics.get("UI") == "N":
					if parsed_metrics.get("CVSS") == "4.0":
						if parsed_metrics.get("VC") == "H" or parsed_metrics.get("VI") == "H" or parsed_metrics.get("VA") == "H":
							filteredList.append(vuln)
					else:
						if parsed_metrics.get("C") == "H" or parsed_metrics.get("I") == "H" or parsed_metrics.get("A") == "H":
							filteredList.append(vuln)

		self.vulnList = filteredList


	def filterListByProduct(self, productList):
		affectedProductList = []
		for data in productList:
			if data['product'] == 'All':
				for vuln in self.vulnList:
					if vuln['vendor'] == data['vendor']:
						affectedProductList.append(vuln)
			else:
				for vuln in self.vulnList:
					if vuln['vendor'] == data['vendor'] and vuln['product'] in data['product']:
						affectedProductList.append(vuln)

		self.vulnList = affectedProductList


	def searchForExploit(self):
		url_kev = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
		url_metasploit = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
		url_exploitdb = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


		print ("\n ----- Known Exploited Vulnerabilities ----- \n")

		response = self.session.get(url_kev, headers=self.headers)
		data = response.json()
		for exploit in data["vulnerabilities"]:
			for vuln in self.vulnList:
				if vuln.get("id") in exploit.get("cveID"):
					print(exploit)

		print("\n ----- Metasploit DB ----- \n")

		response = self.session.get(url_metasploit, headers=self.headers)
		data = response.json()
		for exploit in data.values():
			for vuln in self.vulnList:
				if vuln.get("id") in exploit.get("references"):
					print(exploit.get("fullname"))
					break

		print("\n ----- Exploit DB ----- \n")

		response = self.session.get(url_exploitdb, headers=self.headers)
		data = csv.DictReader(io.StringIO(response.text))
		for row in data:
			for vuln in self.vulnList:
				if vuln.get('id') in row.get("codes"):
					print(row)
					break


def main():
	client = VulnerabilityClient()
	product_file = "./produit_clean.csv"


	print("\n ----- National Vulnerability Database ----- \n")
	data = client.get_nvd()
	for vuln in data["vulnerabilities"]:
		interestingFields_nvd = ["id","vendor", "product", "descriptions","published", "versions", "references", "baseScore", "vectorString"]
		vulnObject = client.findKeys(vuln, interestingFields_nvd)
		client.updateList(vulnObject)

	print(client.vulnList)

	print("\n----- List Product -----\n")
	productList = []
	with open(product_file) as f:
		csvData = csv.DictReader(f, delimiter=";")
		for row in csvData:
			productList.append({"vendor": row['Editor/Manufacturer'], "product": row['Software/Firmware']})

	client.filterListByProduct(productList)
	client.filterListByMetrics()
	client.vulnList.append({'id': "CVE-2025-4428", "vendor": "Ivanti", "product": "Ivanti EPMM"})
	client.searchForExploit()


'''
	print("\n ----- Eunisa Vulnerability Database -----\n")
	data = client.get_euvd()
	for vuln in data['items']:
		vulnObject = {}
		for id in vuln['aliases'].split("\n"):
			if "CVE-" in id:
				vulnObject['id'] = id
				break
		vulnObject['vectorString'] = vuln['baseScoreVector']
		interestingFields_euvd = ["product", "description", "dateUpdated", "baseScore", "references"]
		vulnObject = client.findKeys(vuln, interestingFields_euvd, vulnObject)
		if "id" in vulnObject:
			client.updateList(vulnObject)

	print("\n ----- Github Advisory Database ----- \n")
	data = client.get_gad()
	for vuln in data["data"]["securityVulnerabilities"]["nodes"]:
		vulnObject = {}
		for item in vuln["advisory"]["identifiers"]:
			if item["type"] == "CVE":
				vulnObject['id'] = item["value"]
		vulnObject["vectorString"] = vuln["advisory"]["cvss"]["vectorString"]
		vulnObject = vulnObject | vuln
		if "id" in vulnObject:
			client.updateList(vulnObject)

	client.filterListByMetrics()
	print(client.getList())

	

	test_filepath = "./manual_data.json"
	with open(test_filepath, "r") as f:
		testData = json.load(f)

	client.vulnList = []
	client.vulnList.append(testData)

	print(client.vulnList)
	client.searchForExploit()

'''


if __name__ == "__main__":
	main()