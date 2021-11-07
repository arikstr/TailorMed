import time
import requests
import csv

file_path = '/Users/astrul/Downloads/urls.csv'
apikey = '5136c18cb7e08100c7f5ad201280f9e52d4e847506e119636a4ced2edae86721'

requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False
domainErrors = []
delay = {}


# scan the domain to ensure results are fresh
def DomainScanner(domain):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}

    # attempt connection to VT API and save response
    try:
        conn = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')

    # sanitize domain after upload for safety
    print(domain)
    print(conn)

    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if conn.status_code == 200:

        try:
            jsonResponse = conn.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] != 1:
                print('There was an error submitting the domain for scanning.')
                print(jsonResponse['verbose_msg'])
            else:
                print('{!s} was scanned successfully.'.format(domain))

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domain))
            domainErrors.append(domain)

    # API TOS issue handling
    elif conn.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')


def DomainReportReader(domain, delay):
    # check to see if we have a delay in the report being available
    # if we do, delay for a little bit longer in hopes of the report being ready
    if delay:
        if domain in delay:
            time.sleep(25)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}

    # attempt connection to VT API and save response as r
    try:
        conn = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)
        exit(1)

    if conn.status_code == 200:
        jsonResponse = conn.json()
        # print error if the scan had an issue
        if jsonResponse['response_code'] == 0:
            print('There was an error submitting the domain for scanning.')
        else:
            print('Report is ready for', domain)

        #print(jsonResponse)
        scandate = jsonResponse['scan_date']
        positives = jsonResponse['positives']
        total = jsonResponse['total']

        if positives > 0:
            tag = 'risk'
        elif positives == 0:
            tag = 'safe'

        # inform the user if there were any errors encountered
        count = len(domainErrors)
        if count > 0:
            print('There were {!s} errors scanning domains'.format(count))
            print(domainErrors)

        data = [scandate, domain, positives, total, tag ]
        return data

    # API TOS issue handling
    elif conn.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')

        # Retry Mechanism
        time.sleep(25)
        DomainReportReader(domain, delay)


# open results file and write header
try:
    rfile = open('results.csv', 'w+', newline='')
    dataWriter = csv.writer(rfile, delimiter=',')
    header = ['Scan Date', 'Domain', '# of Positive Scans', '# of Total Scans', 'Tagging', 'Permalink']
    dataWriter.writerow(header)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)

try:
    # read domains from file and pass them to DomainScanner and DomainReportReader
    with open(file_path, 'r') as infile:  # keeping the file open because it shouldnt
        # be opened/modified during reading anyway
        for domain in infile:
            domain = domain.strip('\n')
            try:
                delay = DomainScanner(domain)
                data = DomainReportReader(domain, delay)
                if data:
                    dataWriter.writerow(data)
                    time.sleep(20)  # wait for VT API rate limiting
            except Exception as err:  # keeping it
                print('Encountered an error but scanning will continue.', err)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)
