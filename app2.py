import requests
import json
import shutil
import webbrowser
import os
from tabulate import tabulate
from colorama import Fore, Style, init
from pyfiglet import figlet_format
import folium
import time

# Initialize Colorama for Windows support
init()

# Define colors
cyan = Fore.CYAN
green = Fore.GREEN
red = Fore.RED
yellow = Fore.YELLOW
reset = Style.RESET_ALL

# OSINTTool for handling JSON search (from the third script)
class OSINTTool:
    def __init__(self, json_files):
        self.json_files = json_files
        self.data = self.load_json_data()

    def load_json_data(self):
        data = []
        for json_file in self.json_files:
            try:
                with open(json_file, 'r') as f:
                    data.extend(json.load(f))
            except FileNotFoundError:
                print(f"File not found: {json_file}. Skipping this file.")
            except json.JSONDecodeError:
                print(f"Error decoding JSON in file: {json_file}. Skipping this file.")
        return data

    def search_data(self, search_term):
        results = []
        for item in self.data:
            if search_term.lower() in str(item).lower():
                results.append(item)
        return results

    def print_results(self, results):
        if results:
            headers = list(results[0].keys()) if results else []
            table = [list(result.values()) for result in results]
            print(tabulate(table, headers, tablefmt='psql'))
        else:
            print("No results found.")

# Functions for the first and second scripts
def get_ip_info(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        ip_info = response.json()
        data = [
            ["IP Address", ip_info.get('query')],
            ["Country", ip_info.get('country')],
            ["Region", ip_info.get('regionName')],
            ["City", ip_info.get('city')],
            ["ISP", ip_info.get('isp')]
        ]
        print(tabulate(data, headers=["Field", "Value"], tablefmt="pretty"))
        return ip_info
    except requests.RequestException as e:
        print(f"{red}Error fetching IP info: {str(e)}{reset}")
        return None

def get_phone_info(phone_number):
    try:
        api_key = 'api-key'  # Replace with your actual API key
        url = f'https://api.apilayer.com/number_verification/validate?number={phone_number}'
        headers = {'apikey': api_key}
        response = requests.get(url, headers=headers)
        phone_info = response.json()
        data = [
            ["Phone Number", phone_info.get('number')],
            ["Country", phone_info.get('country_name')],
            ["Location", phone_info.get('location')],
            ["Carrier", phone_info.get('carrier')],
            ["Line Type", phone_info.get('line_type')]
        ]
        print(tabulate(data, headers=["Field", "Value"], tablefmt="pretty"))
        return phone_info
    except requests.RequestException as e:
        print(f"{red}Error fetching phone info: {str(e)}{reset}")
        return None

def get_email_info(email):
    try:
        hunter_api_key = 'api-key'  # Replace with your actual Hunter API key
        response = requests.get(f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunter_api_key}')
        email_info = response.json()
        data = [
            ["Email", email],
            ["Format Valid", str(email_info['data'].get('format_valid'))],
            ["Disposable", str(email_info['data'].get('disposable'))],
            ["Domain", email_info['data'].get('domain')]
        ]
        print(tabulate(data, headers=["Field", "Value"], tablefmt="pretty"))
        return email_info
    except requests.RequestException as e:
        print(f"{red}Error fetching email info: {str(e)}{reset}")
        return None

# Functions for IP locator, creating map, and social media search
def ip_locater(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data['status'] == 'success':
            return {
                'lat': data['lat'],
                'lon': data['lon'],
                'city': data['city'],
                'region': data['regionName'],
                'country': data['country'],
                'isp': data['isp']
            }
        else:
            print(f"{red}Error: {data['message']}{reset}")
            return None
    except requests.RequestException as e:
        print(f"{red}Error: {e}{reset}")
        return None

def create_map(ip_data):
    if not ip_data:
        return
    map_location = folium.Map(location=[ip_data['lat'], ip_data['lon']], zoom_start=10)
    folium.Marker(
        location=[ip_data['lat'], ip_data['lon']],
        popup=f"IP Location: {ip_data['city']}, {ip_data['region']}, {ip_data['country']}\nISP: {ip_data['isp']}",
        tooltip="Click for more info"
    ).add_to(map_location)
    map_location.save("ip_location_map.html")
    print(f"{green}Map has been saved as 'ip_location_map.html'.{reset}")
    webbrowser.open("ip_location_map.html")

def social_media_search(username):
    socialmedia_sites = [
        "instagram.com", 
        "facebook.com", 
        "twitter.com", 
        "github.com", 
    ]
    found_profiles = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    
    for site in socialmedia_sites:
        url = f"https://{site}/{username}"
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                print(f"{green}[+] Profile found: {url}{reset}")
                found_profiles.append(url)
            else:
                print(f"{red}[-] No profile on {site} for username: {username}{reset}")
        except requests.RequestException as e:
            print(f"{red}[-] Error checking {site}: {e}{reset}")
        
        # Adding delay between requests to avoid being rate-limited
        time.sleep(1)
    
    if not found_profiles:
        print(f"{red}No social media profiles found for {username}.{reset}")
    
    return found_profiles

# Main function with a combined menu
def main():
    print_banner()
    while True:
        print(f"{yellow}[1] IP Lookup OSINT")
        print(f"{yellow}[2] Phone Number OSINT")
        print(f"{yellow}[3] Email OSINT")
        print(f"{yellow}[4] IP Locator & Map Creation")
        print(f"{yellow}[5] Social Media Search")
        print(f"{yellow}[6] Search Data in JSON Files")
        print(f"{yellow}[7] Exit")

        choice = input(f"{cyan}Enter your choice: {reset}")

        if choice == '1':
            ip_address = input("Enter IP address: ")
            get_ip_info(ip_address)
        elif choice == '2':
            phone_number = input("Enter phone number: ")
            get_phone_info(phone_number)
        elif choice == '3':
            email = input("Enter email: ")
            get_email_info(email)
        elif choice == '4':
            ip_address = input("Enter IP address: ")
            ip_data = ip_locater(ip_address)
            if ip_data:
                create_map(ip_data)
        elif choice == '5':
            username = input("Enter social media username: ")
            social_media_search(username)
        elif choice == '6':
            json_files = ['Muzzaffarnagar1.json', 'MobileNumbers.json']
            tool = OSINTTool(json_files)
            search_term = input("Enter name or mobile number to search: ")
            results = tool.search_data(search_term)
            tool.print_results(results)
        elif choice == '7':
            print(f"{yellow}Exiting...{reset}")
            break
        else:
            print(f"{red}Invalid choice, please try again!{reset}")

# Print the banner
def print_banner():
    banner_content = figlet_format("OI HINT", font="slant")
    print(f"{green}{banner_content}{reset}")

if __name__ == '__main__':
    main()
