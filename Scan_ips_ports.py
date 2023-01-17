import nmap
import os
import sys
import time
import socket
import random
import pyfiglet
import subprocess
import re

from progress.bar import Bar
from datetime import datetime
os.system("cls")
os.system("color 5")
print("""                                                                                                    
              .:^^^^:.                                              
         ^JB&@@@@@@@@@@&#5~.                                        
      .5&@@@@@@@@@@@@@@@@@@@B^                                      
     Y@@@@@@@@@@@@@@@@@@@@@@@@#:                                    
    #@@@@@@@@@@@@@@@@@@@@@@@@@@@?                                   
   #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@7                                  
  J@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                  
 .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@7                                 
 7@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@P     _  __     __ _____  _   _   ___   __  __                         
 G@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@B    | | \ \   / /|___ / | \ | | / _ \ |  \/  |                        
 #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#   / __) \ \ / /   |_ \ |  \| || | | || |\/| |                        
 B@@G#&@@@@@@@@@@@@@@@@@@@@@&#BG&@G   \__ \  \ V /   ___) || |\  || |_| || |  | |                        
 !@@   .~Y#@@@@@@@@@@@@@&Y^.   .@@~   (   /   \_/   |____/ |_| \_| \___/ |_|  |_|                        
  B@B      .5@@@@@@@@@#^      :&@B     |_|                        
   #@#.      .B@@@@@@J       ?@@&                                   
    B@@P:      G@@@@?     .J&@@&.                                   
     J@@@&G?^:..@@@&..^?P&@@@@G                                     
      :&@@@@@@@@@@@@@@@@@@@@@7                                      
        J@@@@@@@@@@@@@@@@@@B.                                       
         .P@@@@@@@@@@@@@@#~                                         
           .Y&@@@@@@@@@G^                                           
              :75GGPJ^  Done by 


              """)

T1 = "$QAYS93"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)

T1 = "-----------"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)
# read IPs from file
with open('ips.txt', 'r') as f:
    ips = f.read().splitlines()

# scan for active IPs
nm = nmap.PortScanner()
active_ips = []
print("ips : ",ips)
######################################################
T1 = "-----------"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)
for ip in ips:

    try:
        nm.scan(ip, '1-1024')
        #nm.scan(ip, arguments='-F')
        if nm[ip].state() == 'up':
            active_ips.append(ip)
            
    except KeyError:
        print(f"error: Failed to scan {ip}")

####RE####
print("active_ips : ",active_ips)
##########

# write active_ips to file
with open('ips_active.txt', 'w') as f:
    for ip in active_ips:
        f.write(ip + '\n')


######################################################
T1 = "-----------"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)

#Ping for each active ip and get the system type from ttl
system_type={}
# ping the IP addresses
for ip in active_ips:
    try:
        ping_response = subprocess.check_output(["ping", "-n", "1", ip],timeout=5,stderr=subprocess.STDOUT, universal_newlines=True)
        if 'TTL=' in ping_response:
            ttl = int(re.findall("\d+",ping_response)[0])
            print("ttl : "  , ttl)
            if ttl <= 64:
                system_type[ip] = "Linux"
                
            elif ttl > 64 and ttl <= 128:
                system_type[ip] = "Windows"
                
            elif ttl > 128:
                system_type[ip] = "Server"
                
        else:
            print(f"Error: Failed to get ttl for {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to ping {ip}")
        print(e.output)
    except subprocess.TimeoutExpired as e:
        print(f"Error: Failed to ping {ip} - Timed out")
    except Exception as e:
        print(f"Error: Failed to ping {ip}")
        print(e)

####RE####
print("system_type : ",system_type)
##########

# write system_type to file
with open('system_type.txt', 'w') as f:
    for ip, system in system_type.items():
        f.write(ip +  " : " + system + '\n')

######################################################
T1 = "-----------"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)   


# determine the main port for each active IP
main_ports = {}
for ip in active_ips:
    try:
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['name'] in ['http', 'HTTPS', 'SSH', 'FTP', 'Telnet','tcp,udp']:
                main_ports[ip] = port
                
                break
        else:
            main_ports[ip] = None
    except KeyError:
        print(f"error: Failed to determine main port for")


####RE####
print("main_ports : ",main_ports)
##########

# write main_ports to file
with open('main_port.txt', 'w') as f:
    for ip, port in main_ports.items():
        f.write(ip + ': ' + str(port) + '\n')



######################################################
T1 = "-----------"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)

# scan for open ports
open_ports = {}
# Create an instance of the PortScanner class
nm = nmap.PortScanner()

# Scan for open ports for each IP address
for ip in active_ips:
    try:
        nm.scan(ip, arguments='-F')
        open_ports[ip] = nm[ip].all_tcp()
        
    except KeyError:
        print(f"error: Failed to scan for open ports for {ip}")

####RE####
print("open_ports : ",open_ports)
##########


# write open_ports to file
with open('open_ports.txt', 'w') as f:
    for ip, ports in open_ports.items():
        f.write(ip + ': ' + str(ports) + '\n')
T1 = "-----------"  
ASCII_ART_T1 = pyfiglet.figlet_format(T1)
print(ASCII_ART_T1)


######################################################

