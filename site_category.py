import requests
import json
import re

apikey = '5136c18cb7e08100c7f5ad201280f9e52d4e847506e119636a4ced2edae86721'
file_path = '/Users/astrul/Downloads/urls.csv'
url = 'https://www.virustotal.com/vtapi/v2/domain/report'

with open(file_path) as file:
    while (line := file.readline().rstrip()):
        print("URL is: {0}".format(line))

        params = {'apikey': apikey, 'domain': line}
        response = requests.get(url, params=params)

        if response.status_code == 200:

            jsonResponse = response.json()

            if re.compile(r'^category$'):
                first_key = list(jsonResponse.keys())[0]
                first_value = list(jsonResponse.values())[0]
                second_key = list(jsonResponse.keys())[1]
                second_values = list(jsonResponse.values())[1]

                print("According to Website: {0}, the Category is: {1}".format(first_key, first_value))
                if "category" in second_key:
                    print("According to Website: {0}, the Category is: {1}".format(second_key, second_values))
                print()
            else:
                print("There is no Category for this Website ")

        elif response.status_code == 204:
            print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
