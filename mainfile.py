import subprocess
from pyfiglet import figlet_format
from colorama import Fore, Style, init
import folium


# Define colors
cyan = Fore.CYAN
green = Fore.GREEN
red = Fore.RED
yellow = Fore.YELLOW
reset = Style.RESET_ALL

# Print the banner
def print_banner():
    banner_content = figlet_format("OSint.web", font="slant")
    print(f"{green}{banner_content}{reset}")

def option_1():
    print("Running the WebCheck script...")
    try:
        # Using raw string to handle the file path correctly
        subprocess.run(["python", r"C:\Users\Downloads\resume\Learner\src\src\app4.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running the script: {e}")

def option_2():
    print("Running the OSINT script...")
    try:
        # Execute the external script
        subprocess.run(["python", r"C:\Users\Downloads\resume\Learner\src\src\OIHINT-Framework.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running the script: {e}")

def main():
    print_banner()  # Display the banner
    while True:
        print("\nChoose an option:")
        print("1. WebGuard Analyzer")
        print("2. OIHINT-Framework")
        
        choice = input("Enter your choice (1 or 2): ")

        if choice == '1':
            option_1()
            break
        elif choice == '2':
            option_2()
            break
        else:
            print("Invalid choice. Please select 1 or 2.")

if __name__ == "__main__":
    main()
