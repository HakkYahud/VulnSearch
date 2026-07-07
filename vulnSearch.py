import requests
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)
SEARCHTIME = NOW - timedelta(days=30)
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
		    "cvssV3Metrics": "AV:N/AC:L/PR:N",
		    "resultsPerPage": 3,
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
			securityAdvisories (first:5) {
				nodes {
					ghsaId,
					summary,
					severity,
					updatedAt,
					permalink,
					cvss{
						score,
						vectorString
					},
					identifiers {
						type,
						value
					}
				},
			}
		}
		'''

		response = self.session.post(url, headers=headers, json={"query":query})
		return response.json()

	def get_euvd(self):
		url = "https://euvdservices.enisa.europa.eu/api/search?fromScore=8&toScore=10"
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


def main():
	client = VulnerabilityClient()

	print("\n ----- National Vulnerability Database ----- \n")
	data = client.get_nvd()
	for vuln in data["vulnerabilities"]:
		interestingFields_nvd = ["id","product", "descriptions","published", "versions", "references", "baseScore", "vectorString"]
		vulnObject = client.findKeys(vuln, interestingFields_nvd)
		client.updateList(vulnObject)

	print("\n ----- Eunisa Vulnerability Database -----\n")
	data = client.get_euvd()
	for vuln in data['items']:
		vulnObject = {}
		for id in vuln['aliases'].split("\n"):
			if "CVE-" in id:
				vulnObject['id'] = id
		interestingFields_euvd = ["description", "dateUpdated", "baseScore", "references"]
		vulnObject = client.findKeys(vuln, interestingFields_euvd, vulnObject)
		client.updateList(vulnObject)

	print ("\n ----- Github Advisory Database ----- \n")
	data = client.get_gad()
	for vuln in data["data"]["securityAdvisories"]["nodes"]:
		vulnObject = {}
		for item in vuln["identifiers"]:
			if item["type"] == "CVE":
				vulnObject['id'] = item["value"]
		vulnObject = vulnObject | vuln
		client.updateList(vulnObject)

	print(client.getList())
if __name__ == "__main__":
	main()