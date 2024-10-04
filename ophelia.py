#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on  Oct 1 14:46:30 2024

@author: xenon
"""

import socket, sys, os, re, random, optparse, time, io
import logging
import webbrowser
import ipaddress
import speedtest


# Configure logging
logging.basicConfig(filename='ophelia_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_action(action):
    logging.info(action)
    
    
#Character (Name with Ophelia)
class Ophelia:
    def Ai_Lian(self):
        self.responses = {
            "hello": [
                "Hello! Hope you're having a great day! How can I help?",
                "Hi there! What’s new with you today?",
                "Hello! What interesting things are you up to today?",
                "Hi! I’m curious to know what you’d like to discuss!",
                "Hello! Is there something specific you’d like to know?",
                "Hi! It's a pleasure to chat with you! What can I help with?",
                "Hello! I’m here for you, so feel free to ask anything.",
                "Hey there! Let’s make today productive! What’s your question?",
                "Hello! Ready for some fun? What’s your query?",
                "Hi! I promise I’m more fun than a regular chatbot! What’s up?",
                "Greetings! I’m all ears for your questions!"
            ],
            "hi": [
                "Hi there! How can I assist you today?",
                "Hello! It's great to see you! What brings you here?",
                "Hey! How can I help you on this fine day?",
                "Hello! What’s on your mind today?",
                "Hi! What can I do for you right now?",
                "Hey there! What’s up?",
                "Greetings! I'm here to help you with anything you need!",
                "Hello! Excited to chat with you! How can I assist?",
                "Hi! I’m thrilled to be here! What’s your question?",
                "Hey! How's your day going? What can I do for you?",
            ],
            "how are you?": [
                "I'm just a program, but I'm here and ready to help you!",
                "Doing great, thanks! How about you?",
                "I'm here and excited to assist you! What can I do for you today?",
                "Feeling fantastic! What would you like to talk about?",
                "I'm doing well, thanks for asking! How can I make your day better?"
            ],
            "ophelia": [
                "Yes, that's me! How can I help you?", 
                "You know I love it when you say my name!", 
                "Aww, hearing my name from you always makes me smile",
                "You made my day by saying my name!",
                "Hey there! You called?"
            ],
            
            
            "bye": [
                "Goodbye!", 
                "See you later!", 
                "Take care!"
            ],
        }

            
        self.ophelia_data = {
            "name": "Ai Lian",
            "english_name": "Ophelia",
            "dob": "1980-08-18",
            "education": "Higher Diploma in Fashion Design from HKDI",
            "skills": {
                "scanning": [
                    "Scanning with nmap",
                    "Textile technology"
                ],
            }
        }



    def get_response(self, user_input):
        user_input = user_input.lower()
        for key in self.responses.keys():
            if key in user_input:
                return random.choice(self.responses[key])
        return "That's interesting.That is the new one for me .Can you explain for that "



    def get_name(self):
        return f"Ophelia: I am {self.ophelia_data['name']} (also known as {self.ophelia_data['english_name']})."
    
    
    def get_dob(self):
        return f"Ophelia:I born in {self.ophelia_data['dob']}."
    
    
    
#ASCII art section
#respberry pi pico art    
def raspberry_pi_pico_schematic_ascii_art():
    ascii_art = r"""
   Schematic Diagram
   
                |power usb|                           
        +--------------------------+   
        |     Raspberry Pi Pico     | 
        |GP0                    VBUS| 
        |GP1                    VSYS|  
        |GND                     GND| 
        |GP2                  3V3_EN| 
        |GP3                 3V3_OUT|
        |GP4                ADC_VREF| 
        |GP5                 GP28_A2| 
        |GND                    AGND|      
        |GP6                 GP27_A1| 
        |GP7                 GP26_A0| 
        |GP8                     RUN| 
        |GP9                    GP22| 
        |GND                     GND| 
        |GP10                   GP21| 
        |GP11                   GP20| 
        |GP12  K          0     GP19| 
        |GP13  L          1     GP18| 
        |GND   C          D      GND| 
        |GP14  W          W     GP17| 
        |GP15  S    GND   S     GP16| 
        |      |    |     |         | 
        +--------------------------+

    """
    print(ascii_art)    


    
#About Author 
def about():
    content_about = r"""
    ---------------------------------------------------------
                ILLUMINATING THE DIGITAL WORLD
    =========================================================

         _     _                                      
      ,- 9___f L-.                                   
      : / O u O \ ;                                   
       /"[:===;]"\                                    
      / __ `v' __ \                                   
     /  \_){O}(_/  \                                  
       &/' ;-: `;..                                   
      @' ,VAVAV.\@/                                   
         |/|//\|  \                                   
         ' (}  '   \                                  
           |\\_     \                                 
           d'\\c|     \                                
          /_; \\|                                      

    Being a hacker means not accepting the world 
     as it is, but working to improve it. 
     
     
     Author: Xenon Bytechef (Burma)
     File : ophelia.py
     Date : [oct/4/2024]
    ----------------------------------------------------------
    """
    print(content_about)
    
    
    
    
#command Helping service function
def help_ophelia():
    log_action("Displaying help information")
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
          That is Python AI model named Ophelia. The purpose is to help Penetration Testers in their work.
          This AI started on Oct 1, 2024, and will continue to develop in the future.
          
          User manual:
              browse <web name> : Browse to the respective website.
              <youtube,osintframe,Dns lookup,wayback machine,Ip2 location,RDp guard,Hacker gpt,panzer,wiki,bin>
              update system : Update your system.
              
              install <pkgname> : Install a specific package.
              <virtual box,sode-os,telegram,spyder,riseup,vlc>
              
              activate nmap : to activate namp scanner function 
              
              note down ophelia:to note down something as note in ophelia
              
              pentest list : to open penetration testing search engine and other tool 
                              list and browsing you want 
            error fix python env:that will error fix the env of python3
            internet speed : to check internet speed 
          """)
          
          
#NOte down function 
def note_down_ophelia():
    
  notes = []
  print("Start noting down. Type 'end' when finished.")
  
  while True:
    line = input("> ")
    if line.lower() == 'end':
      break
    notes.append(line)

  if notes:
    filename = input("Enter filename to save the note (e.g., ophelia_notes.txt): ")
    with open(filename, 'a') as f:
      for note in notes:
        f.write(note + '\n')
    print(f"Notes saved to {filename}")
  else:
    print("No notes were taken.")


    
#Browsing Service 
#penetration search engine and other lis
def pentest_service():


    # List of services categorized by type
    services = [
        {
            "Category": "Search Engine",
            "Name": "Shodan",
            "URL": "https://www.shodan.io"
        },
        {
            "Category": "Search Engine",
            "Name": "Censys",
            "URL": "https://censys.com/"
        },
        {
            "Category": "Search Engine",
            "Name": "Onyphe",
            "URL": "https://www.onyphe.io/"
        },
        {
            "Category": "Search Engine",
            "Name": "Bin",
            "URL": "https://messenger.microsoft.com"
        },
        {
            "Category": "Search Engine",
            "Name": "ZoomEye",
            "URL": "https://www.zoomeye.hk/"
        },
        {
            "Category": "Search Engine",
            "Name": "Binary Edge",
            "URL": "https://www.binaryedge.io/"
        },
        {
            "Category": "Search Engine",
            "Name": "Wigle",
            "URL": "https://wigle.net/"
        },
        {
            "Category": "Search Engine",
            "Name": "BuiltWith",
            "URL": "https://builtwith.com/"
        },
        {
            "Category": "Search Engine",
            "Name": "Public WWW",
            "URL": "https://publicwww.com/"
        },
        {
            "Category": "Threat Intelligence",
            "Name": "Pulsedive",
            "URL": "https://pulsedive.com/"
        },
        {
            "Category": "Threat Intelligence",
            "Name": "Urlscan",
            "URL": "https://urlscan.io/"
        },
        {
            "Category": "Vulnerabilities",
            "Name": "Vulners",
            "URL": "https://vulners.com/"
        },
        {
            "Category": "Virus Scan",
            "Name": "VirusTotal",
            "URL": "https://www.virustotal.com"
        },
        {
            "Category": "Virus Scan",
            "Name": "Jotti's Virus Scan",
            "URL": "https://virusscan.jotti.org/it"
        },
        {
            "Category": "IP Lookup",
            "Name": "What is My IP",
            "URL": "https://whatismyip.com/"
        },
        {
            "Category": "IP Lookup",
            "Name": "What's Their IP",
            "URL": "https://whatstheirip.com/"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Intelligence X",
            "URL": "https://intelx.io"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Leakcheck",
            "URL": "https://leakcheck.io"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "We Leak Info",
            "URL": "https://weleakinfo.to"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Leak Peek",
            "URL": "https://leakpeek.com"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Snusbase",
            "URL": "https://snusbase.com"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Leakedsource",
            "URL": "https://wikileaks.org"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "GlobelLeaks",
            "URL": "https://globaleaks.org"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Firefox Monitor",
            "URL": "https://monitor.firefox.com"
        },
        {
            "Category": "Breach Search Engines",
            "Name": "Breach Alarm",
            "URL": "https://breachalarm.com"
        }
    ]
    
    
    
    print("\n")
    for service in services:
        print(f"{service['Category']:20} | {service['Name']:20} | {service['URL']}")

    def browse_service():
        print("\n")
        response = input("Ophelia:Do you want to browse? (yes/no): ").strip().lower()
        if response == "yes":
            service_name = input("Ophelia:Type the website name: ").strip()
            for service in services:
                if service['Name'].lower() == service_name.lower():
                    print(f"Opening {service['Name']} at {service['URL']}")
                    webbrowser.open(service['URL'])
                    return
            print("Ophelia:Sorry, the service you entered is not in the list.")
        else:
            print("Ophelia:Okay, have a nice day!")


    browse_service()



# Browsing section
def youtube():
    log_action("Browsing YouTube")
    print("We are now starting to browse YouTube")
    os.system("firefox https://youtube.com/")



def osintframe():
    log_action("Browsing OSINT Framework")
    print("We are now starting to browse OSINT Framework")
    os.system("firefox https://osintframework.com/")



def dnslookup():
    log_action("Browsing DNS Lookup")
    print("We are now starting to browse DNS Lookup")
    os.system("firefox https://www.nslookup.io/")



def waybackmachine():
    log_action("Browsing Wayback Machine")
    print("We are now starting to browse Wayback Machine")
    os.system("firefox http://web.archive.org/")



def ip2location():
    log_action("Browsing IP2Location")
    print("We are now starting to browse IP2Location")
    os.system("firefox http://ip2location.com")



def rdpguard():
    log_action("Browsing RDPGuard")
    print("We are now starting to browse RDPGuard")
    os.system("firefox https://rdpguard.com")



def hackergpt():
    log_action("Browsing Hacker GPT")
    print("We are now starting to browse Hacker GPT")
    os.system("firefox https://chat.hackerai.co/")



def wiki():
    log_action("Browsing Wikipedia")
    print("We are now starting to browse Wikipedia")
    os.system("firefox https://en.wikipedia.org")
    
    

def panzer():
    log_action("Browsing PanzerRush Game")
    print("We are now starting to browse PanzerRush Game")
    os.system("firefox https://www.panzerrush.com/?e=1")



def bmi():
    log_action("Browsing Microsoft Bin")
    print("We are now starting to browse Microsoft Bin")
    os.system("firefox messenger.microsoft.com/")



def updater():
    log_action("Updating system")
    print("Now! We will update")
    os.system("sudo apt update && sudo apt upgrade -y")
    os.system('clear')
 
    
 
def python3_error():
    os.system('sudo apt install python3-venv')
    os.system('python3 -m venv path/to/venv')
    os.system('source path/to/venv/bin/activate')
    print("Now ready to use!")
    
    


# Install section
def virtualbox_install():
    log_action("Installing VirtualBox")
    os.system("sudo apt update")
    os.system("sudo apt install virtualbox -y")
    os.system("sudo apt install virtualbox-dkms")
    os.system("sudo apt full-upgrade -y")
    os.system("sudo apt install build-essential dkms linux-headers-$(uname -r)")
    print("We installed VirtualBox on your Linux system")
    print("We will reboot")
    os.system("sudo apt purge virtualbox -y && reboot")



def telegram_install():
    log_action("Browsing Telegram download site")
    print("You need to browse and download the file")
    print("We will start browsing the Telegram download website")
    os.system("firefox https://desktop.telegram.org/")



def spyder_install():
    log_action("Installing Python Spyder")
    print("Now! We will install Python Spyder")
    os.system("sudo apt install spyder")



def code_installer():
    log_action("Installing Code-OS")
    print("Now! We will install Code-OS")
    os.system("sudo apt install code-os")



def rise_installer():
    log_action("Installing Rise-UP VPN")
    print("Now! We will install Rise-UP VPN")
    os.system("sudo apt install rise-up")



def vlc_installer():
    log_action("Installing VLC-bin")
    print("Now! We will install VLC-bin")
    os.system("sudo apt install vlc-bin")
    
    
    
#Internet Speed testing Section
def test_speedtest_setup():
        try:
            st = speedtest.Speedtest()


            best_server = st.get_best_server()
            print(f"Connected to {best_server['host']} located in {best_server['country']}.")

            return True
        except Exception as e:
            print(f"Error during speedtest setup: {e}")
            return False
        
        
        
def check_internet_speed():
        st = speedtest.Speedtest()

        st.get_best_server()


        download_speed = st.download() / 1_000_000  
        upload_speed = st.upload() / 1_000_000      


        return {
            'download_speed_mbps': round(download_speed, 2),
            'upload_speed_mbps': round(upload_speed, 2)
        }


#Ipaddress Checking and Scanning to IP


def ip_class():
    def classify_ip(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            classification = f"IP Address: {ip}\n"
            
            # Classify the IP address
            if ip_obj.is_private:
                classification += "Type: Private IP Address\n"
            elif ip_obj.is_loopback:
                classification += "Type: Loopback IP Address\n"
            elif ip_obj.is_reserved:
                classification += "Type: Reserved IP Address\n"
            elif ip_obj.is_global:
                classification += "Type: Global IP Address\n"
            else:
                classification += "Type: Unspecified IP Address\n"

            # Additional details
            classification += "Details:\n"
            classification += "1. Format: "
            if isinstance(ip_obj, ipaddress.IPv4Address):
                classification += "IPv4 (e.g., 192.168.1.1)\n"
                classification += "   Structure: Four decimal numbers (octets) separated by periods.\n"
                classification += "   Range: Each octet ranges from 0 to 255, allowing for approximately 4.3 billion unique addresses.\n"
            else:
                classification += "IPv6 (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)\n"
                classification += "   Structure: Eight groups of four hexadecimal digits separated by colons.\n"
                classification += "   Range: Provides a vastly larger address space (2^128).\n"

            classification += "2. Public vs. Private:\n"
            if ip_obj.is_private:
                classification += "   This is a Private IP Address, used within a local network.\n"
            else:
                classification += "   This is a Public IP Address, accessible over the internet.\n"

            classification += "3. Dynamic vs. Static:\n"
            classification += "   IP addresses can be assigned dynamically via DHCP or statically configured.\n"
            classification += "4. Subnetting:\n"
            classification += "   Subnetting divides a network into smaller sub-networks for better management.\n"

            return classification

        except ValueError:
            return f"{ip} is not a valid IP Address."

    def request_ip():
        ip = input("Ophelia:Please enter an IP address to classify: ")
        result = classify_ip(ip)
        print(result)



    request_ip()
    

          

# Checking for superuser privileges
def check_superuser():
    if os.geteuid() != 0:
        print("This function requires superuser privileges to run.")
        print("Please run the script with 'sudo' or as an administrator.")
        sys.exit(1)

# Nmap scanner function
def nmap_scanner():
    try:
        import nmap
    except ImportError:
        print("[ nmap ] module is missing")
        print("  [*] Please use: 'pip install python-nmap' to install it.")
        sys.exit(1)

    scanner = nmap.PortScanner()
    print("Welcome to our Nmap Scanning Function")
    print("<...............................................>")
    print("\n")

    ip_addr = input("Please input your URL or IP: ")
    print("The IP you input is:", ip_addr)

    print("""\nPlease select the type of scan:
              1. SYN Scan 
              2. UDP Scan 
              3. Comprehensive Scan
              4. TCP Connect Scan
              5. Service Version Detection
              6. Operating System Detection
              7. Aggressive Scan
           """)
    print("\n")

    resp = input("Please input the number corresponding to your desired scan: ")
    print("You have selected option:", resp)

    try:
        # Handling various scan options based on user input
        if resp == '1':
            print("This is a SYN Scan")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-p 1-65535 -v -sS')
            print_scan_info(scanner, ip_addr)

        elif resp == '2':
            print("This is a UDP Scan")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-sU -p 1-65535')
            print_scan_info(scanner, ip_addr)

        elif resp == '3':
            print("This is a Comprehensive Scan")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-sS -sU -p 1-65535')
            print_scan_info(scanner, ip_addr)

        elif resp == '4':
            print("This is a TCP Connect Scan")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-sT -p 1-65535')
            print_scan_info(scanner, ip_addr)

        elif resp == '5':
            print("This is a Service Version Detection")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-sV -p 1-65535')
            print_scan_info(scanner, ip_addr)

        elif resp == '6':
            print("This is an Operating System Detection")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-O -p 1-65535')
            print_scan_info(scanner, ip_addr)

        elif resp == '7':
            print("This is an Aggressive Scan")
            print("Nmap Version:", scanner.nmap_version())
            scanner.scan(ip_addr, arguments='-A -p 1-65535')
            print_scan_info(scanner, ip_addr)

        else:
            print("Error: Invalid option selected!")

    except nmap.PortScannerError as e:
        print(f"PortScannerError: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to display scan results
def print_scan_info(scanner, ip_addr):
    print("Scan Info:", scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())

    protocols = scanner[ip_addr].all_protocols()
    if protocols:
        print("Protocols:", protocols)
        for protocol in protocols:
            print(f"Open Ports ({protocol}):", scanner[ip_addr][protocol].keys())
    else:
        print("No open ports found.")
        
        # Ensure the script is running with superuser privileges
        check_superuser()

        # Run the Nmap scanner
        nmap_scanner()



            

def main():
    ophelia = Ophelia()
    ophelia.Ai_Lian()
    log_action("Assistant AI started")
    print("Welcome to the Assistant AI!")
    print("Type 'exit' to end the conversation.")
    print("If you want to know the usage you can type 'help --ophelia'")

    command_map = {
        "your name": lambda: print(ophelia.get_name()),
        "your birthday": lambda: print(ophelia.get_dob()),
        "how can you help me": lambda: print("I can help you in your penetration work."),
        "update system": lambda: updater() or print("Now finished the updating process!"),
        "activate nmap": nmap_scanner,
        "ip check": ip_class,
        "error fix python env": python3_error,
        "note down ophelia": note_down_ophelia,
        "help --ophelia": help_ophelia,
        "clear": lambda: os.system('cls' if os.name == 'nt' else 'clear'),
        "internet speed": test_internet_speed,
        "pentest list": pentest_service,
        "respberry pico": raspberry_pi_pico_schematic_ascii_art
    }

    while True:
        user_input = input("\nWhat's on your mind: ").lower()

        # Check for exit command
        if user_input == "exit":
            print("Ophelia: Thank you for using the Assistant AI. Goodbye!")
            log_action("Assistant AI session ended")
            break

        # Check for browsing commands
        if "browse" in user_input:
            handle_browsing(user_input)
            continue

        # Check for installation commands
        if "install" in user_input:
            handle_installation(user_input)
            continue

        # Check for any mapped commands
        for command, action in command_map.items():
            if command in user_input:
                action()
                log_action(f"Executed command: {command}")
                break
        else:
            # Handle unknown commands
            response = ophelia.get_response(user_input)
            print("Ophelia:", response)
            log_action(f"User input: {user_input} - Response: {response}")

def handle_browsing(user_input):
    browsing_options = {
        "youtube": youtube,
        "osintframe": osintframe,
        "dnslookup": dnslookup,
        "waybackmachine": waybackmachine,
        "ip2location": ip2location,
        "rdpguard": rdpguard,
        "hackergpt": hackergpt,
        "wiki": wiki,
        "bin": bmi,
        "panzer": panzer
    }
    
    for site, action in browsing_options.items():
        if site in user_input:
            action()
            return
    user_link = input("That’s not in my data link. Can I get a link: ")
    os.system("firefox " + user_link)
    log_action(f"Browsing custom link: {user_link}")
    print("We are now going to", user_link)

def handle_installation(user_input):
    installation_options = {
        "virtualbox": virtualbox_install,
        "code-os": code_installer,
        "telegram": telegram_install,
        "spyder": spyder_install,
        "rise-up": rise_installer,
        "vlc": vlc_installer
    }
    
    for package, action in installation_options.items():
        if package in user_input:
            action()
            return
    user_command = input("That’s not in my data! Can I get a command: ")
    os.system(user_command)
    log_action(f"Executed custom command: {user_command}")

def test_internet_speed():
    test_speedtest_setup()
    speeds = check_internet_speed()
    print(f"Download speed: {speeds['download_speed_mbps']} Mbps")
    print(f"Upload speed: {speeds['upload_speed_mbps']} Mbps")

main()



    