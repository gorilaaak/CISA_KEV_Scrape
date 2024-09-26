import requests
import argparse

key_mapping = {
    "cveID": "CVE",
    "vendorProject": "Vendor",
    "product": "Product",
    "dateAdded": "Date_Added",
    "shortDescription": "Description",
    "notes": "Notes",
    "knownRansomwareCampaignUse": "UsedbyGroups"
}

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--date", type=str, dest="target", help="Please specify the date in format YYYY-MM-DD")
    options = parser.parse_args()
    if not options:
        parser.error("[-] Please specify an target date, use --help for more info")
    return options

def pullData():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        json_rsp = response.json()
        return json_rsp
    except requests.exceptions.ConnectionError:
        raise ConnectionError("Connection failed. Please check your internet connection.")

def parseonDate(dateFilter, json_rsp):
    filter = [date for date in json_rsp['vulnerabilities'] if dateFilter in date['dateAdded']]
    mapped_json_array = [
    {new_key: item[old_key] for old_key, new_key in key_mapping.items() if old_key in item}
    for item in filter ]
    return mapped_json_array


def output_json_to_file(json_data, file_path):
    with open(file_path, 'w') as file:
        for item in json_data:
            file.write(f"{'CVE:':<15} {item['CVE']}\n")
            file.write(f"{'Vendor:':<15} {item['Vendor']}\n")
            file.write(f"{'Product:':<15} {item['Product']}\n")
            file.write(f"{'Date Added:':<15} {item['Date_Added']}\n")
            file.write(f"{'Description:':<15} {item['Description']}\n")
            file.write(f"{'Notes:':<15} {item['Notes']}\n")
            file.write(f"{'Used by Groups:':<15} {item['UsedbyGroups']}\n")
            file.write("=" * 40 + "\n")  # Separator line



options = get_arguments()
final_data = parseonDate(options.target, pullData())
output_json_to_file(final_data, 'output.txt')