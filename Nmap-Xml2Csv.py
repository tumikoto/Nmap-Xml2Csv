import argparse
import csv
import xml.etree.ElementTree as ET


def parse_nmap_results(nmap_xml_file, csv_output_file):
    # Parse the Nmap XML file and create a list of dictionaries containing the target IP address, port number, port status, protocol, service name, and service version information
    results = []
    root = ET.parse(nmap_xml_file).getroot()
    for host in root.findall('host'):
        target = host.find('address').attrib['addr']
        for port in host.findall('ports/port'):
            port_number = port.attrib['portid']
            port_status = port.find('state').attrib['state']
            protocol = port.attrib['protocol']
            service_name = port.find('service').attrib['name']
            service_product = port.find('service').attrib.get('product', '')
            service_version = port.find('service').attrib.get('version', '')
            results.append({'Target': target, 'Port': port_number, 'Status': port_status, 'Protocol': protocol, 'Service': service_name, 'Product': service_product, 'Version': service_version})

    # Write the results to a CSV file
    with open(csv_output_file, 'w', newline='') as csvfile:
        fieldnames = ['Target', 'Port', 'Status', 'Protocol', 'Service', 'Product', 'Version']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)


if __name__ == '__main__':
    # Define command-line arguments
    parser = argparse.ArgumentParser(description='Parse an Nmap XML output file into a CSV file.')
    parser.add_argument('input_file', help='path to the Nmap XML input file')
    parser.add_argument('output_file', help='path to the CSV output file')

    # Parse command-line arguments
    args = parser.parse_args()

    # Call the parse_nmap_results function with the input and output file paths
    parse_nmap_results(args.input_file, args.output_file)