from pymisp import PyMISP
from ipwhois import IPWhois
import json
from cymon import Cymon
from virus_total_apis import PublicApi as VirusTotalPublicApi
import threatcrowd
from termcolor import colored
import argparse


# WHOIS Lookup **Clean UP**
def whois_lookup(ip):
    obj = IPWhois(ip)
    results = obj.lookup_whois()
    print colored('WHOIS Results:', 'red')
    print json.dumps(results, sort_keys=True, indent=4, separators=(',', ': '))


# MISP Lookup
def misp_lookup(ip):
    misp_url = 'http://172.20.12.13/'
    misp_key = 'pBEhWOvMulC7MuQIS1A3OQwRa3CojpiyeRUPhQCk'
    misp = PyMISP(misp_url, misp_key, False, 'json')

    result = misp.search_all(value=ip)
    try:
        for event in result['response']:
            print (event['Event']['info'])
            print(misp_url + 'events/view/%s' % event['Event']['id'])
            print '\n'
    except KeyError:
        print 'No Events Found'

# JIRA *Need to figure out API


# PASSIVETOTAL *Need API Key


# ThreatCrowd
def threatcrowd_lookup(ip):
    tc = threatcrowd.ip_report(ip)
    try:
        tc_link = tc['permalink']
        print 'Information Found...go to link for more information'
        print tc_link
    except KeyError:
        print "No ThreatCrowd Information Found"
        pass


# Virustotal Lookup
def vt_lookup(ip):
    API_KEY = 'abecb34b55f4c17932a22ce0eae65950d8d684f94f6587f0619a16e0c24a4daa'
    vt = VirusTotalPublicApi(API_KEY)
    response = vt.get_ip_report(ip)
    data = response['results']
    #print json.dumps(response)

    try:
        total_detected_comm_samples = 0
        for dcs in data['detected_communicating_samples']:
            #print '****** %s' % dcs['sha256']
            total_detected_comm_samples += 1
        print 'Total Detected Communicating Samples: %s' % total_detected_comm_samples

        total_undetected_samples = 0
        for uds in data['undetected_downloaded_samples']:
            total_undetected_samples += 1
        print 'Total Undetected Samples: %s' % total_undetected_samples

        detected_urls = 0
        for url in data['detected_urls']:
            detected_urls += 1
        print 'Total Detected URLs: %s' % detected_urls

        resolutions = 0
        for res in data['resolutions']:
            resolutions += 1
        print 'Total Resolutions: %s' % resolutions
    except KeyError:
        print 'No VirusTotal Information Found'


# Cymon
def cymon_lookip(ip):
    api = Cymon('5a366127a89c16fe95445967b3d73de7ab2c232c')
    response = api.ip_events(ip)
    print colored('Found %s reports in Cymon...Showing the latest' % response['count'], 'magenta')
    for e in response['results']:
        print e['title']
        print e['updated']
        print e['details_url']
        print ('\n')

# IBM X-Force

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Grab information related to an IP address')
    parser.add_argument("-i", "--ip", required=True, help="IP Address to Search")

    args = parser.parse_args()

    print ('\n\n')
    whois_lookup(args.ip)
    print ('\n\n')
    print colored('Looking Up MISP Events....', 'green')
    misp_lookup(args.ip)
    print ('\n\n')
    print colored('Looking Up ThreatCrowd Information....', 'yellow')
    threatcrowd_lookup(args.ip)
    print ('\n\n')
    print colored('Looking Up VirusTotal Information....', 'blue')
    vt_lookup(args.ip)
    print ('\n\n')
    print colored('Looking Up Cymon Information....', 'magenta')
    cymon_lookip(args.ip)
