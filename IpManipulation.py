import ipaddress
from colorama import Fore
import re
import socket
import netifaces
from scapy.all import ARP, Ether, srp
import psutil

questions_color = Fore.RED
answers_color = Fore.BLUE
answers_result_color = Fore.MAGENTA

def find_class(ip):
    """Determines the class of an IP address."""
    first_octet = int(ip[0])  # Extract first octet as an integer
    if 0 <= first_octet <= 127:
        if first_octet == 10:
            return "Private"
        return "A"
    elif 128 <= first_octet <= 191:
        if first_octet == 172 and 16 <= int(ip[1]) <= 31:
            return "Private"
        return "B"
    elif 192 <= first_octet <= 223:
        if first_octet == 192 and 168 == int(ip[1]):
            return "Private"
        return "C"
    elif 224 <= first_octet <= 239:
        # Multicast address
        return "D"
    else:
        # Reserved address
        return "E"


def separate(ip, class_name):
    """Separates network and host ID from the given IP address."""
    if class_name == "A":
        network_address = ip[0]
        host_address = ".".join(ip[1:])  # Join remaining octets with dots
    elif class_name == "B":
        network_address = ".".join(ip[:2])  # Join first two octets
        host_address = ".".join(ip[2:])
    elif class_name == "C":
        network_address = ".".join(ip[:3])  # Join first three octets
        host_address = ip[3]

    elif class_name == "Private":
        if int(ip[0]) == 10:
            print(answers_color +"\nClass A private address")
            network_address = ip[0]
            host_address = ".".join(ip[1:])  # Join remaining octets with dots
        if (int(ip[0]) == 172) and (16 <= int(ip[1]) <= 31):
            print(answers_color +"\nClass B private address")
            network_address = ".".join(ip[:2])  # Join first two octets
            host_address = ".".join(ip[2:])
        if (int(ip[0]) == 192) and ( int(ip[1]) == 168):
            print(answers_color +"\nClass C private address")
            network_address = ".".join(ip[:3])  # Join first three octets
            host_address = ip[3]

    else:
        print(answers_color +"In this class, IP address is not divided into Network and Host ID")
        return

    print(answers_color + "Network Address is:",answers_result_color + network_address)
    print(answers_color + "Host Address is:",answers_result_color + host_address)

def subnet(ip):
    while True:
        print(questions_color + "Options:")
        print(questions_color + "1. Find Hosts")
        print(questions_color + "2. Find Subnets")
        print(questions_color + "3. Find Supernets")
        print(questions_color + "4. Exit" + Fore.RESET)
        
        choice = input("Enter your choice: ")
        if choice == "1":
            print(answers_color + "Hosts: ",answers_result_color , list(ipaddress.ip_network(ip).hosts()))

        if choice == "2":
            while True:
                print(questions_color + "Options:")
                print(questions_color + "1. default")
                print(questions_color + "2. prefixlen_diff EX:2")
                print(questions_color + "3. new_prefix EX:26")
                print(questions_color + "4. Exit" + Fore.RESET)

                sub_choice = input("Enter your action: ")
                if sub_choice == "1":
                    print(answers_color + "Subnets: \n",answers_result_color , list(ipaddress.ip_network(ip).subnets()))
                if sub_choice == "2":
                    len_num = int(input("Enter your prefix_diff length: "))
                    print(answers_color + "Subnets: \n",answers_result_color , list(ipaddress.ip_network(ip).subnets(prefixlen_diff=len_num)))
                if sub_choice == "3":
                    len_num = int(input("Enter your new_prifix: "))
                    print(answers_color + "Subnets: \n",answers_result_color , list(ipaddress.ip_network(ip).subnets(new_prefix=len_num)))
                if sub_choice == "4":
                    break
        elif choice == "3":
            while True:
                print(questions_color + "Options:")
                print(questions_color + "1. default")
                print(questions_color + "2. prefixlen_diff EX:2")
                print(questions_color + "3. new_prefix EX:20")
                print(questions_color + "4. Exit" + Fore.RESET)

                sub_choice = input("Enter your action: ")
                if sub_choice == "1":
                    print(answers_color + "Subnets: \n",answers_result_color , list(ipaddress.ip_network(ip).supernet()))
                if sub_choice == "2":
                    len_num = int(input("Enter your prefix_diff length: "))
                    print(answers_color + "Subnets: \n",answers_result_color , list(ipaddress.ip_network(ip).supernet(prefixlen_diff=len_num)))
                if sub_choice == "3":
                    len_num = int(input("Enter your new_prifix: "))
                    print(answers_color + "Subnets: \n",answers_result_color , list(ipaddress.ip_network(ip).supernet(new_prefix=len_num)))
                if sub_choice == "4":
                    break
        elif choice == "4":
            break

def ip_to_binary(ip_address):
    """Converts an IPv4 address to its binary representation."""
    octets = ip_address.split(".")
    binary_octets = [bin(int(octet))[2:].zfill(8) for octet in octets]
    return ".".join(binary_octets)

def subnet_mask_to_binary(subnet_mask):
    """Converts a subnet mask (CIDR value) to its binary representation."""
    # if CIDR=24 -> 24 "1"'s and 32-24=8 "0"'s
    binary_mask = "1" * subnet_mask + "0" * (32 - subnet_mask)
    return ".".join([binary_mask[i:i+8] for i in range(0, 32, 8)])

def is_valid_ip_address(ip):
    # Regular expression pattern for IP address validation
    pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    
    if re.match(pattern, ip):
        # The IP address is valid
        return True
    else:
        # The IP address is invalid
        return False
    
def get_valid_ip_address():
    while True:
        ip = input("Enter an IP address: ")
        if is_valid_ip_address(ip):
            return ip
        else:
            print("Invalid IP address. Please try again.")

def check_same_network(cidr1, cidr2):
    """Checks if two CIDR blocks represent the same network or subnets of each other.

    Args:
        cidr1 (str): The first CIDR block in the format "IP_address/prefix_length".
        cidr2 (str): The second CIDR block in the format "IP_address/prefix_length".

    Returns:
        bool: True if the networks are the same or subnets of each other, False otherwise.


    192.168.1.0/24
    192.168.1.128/25

    Broadcast address = network_address + 2^(32-CIDR) - 1

    network1_int = 3232235520 (192.168.1.0 in integer form)
    network2_int = 3232235776 (192.168.1.128 in integer form)
    broadcast1_int = 3232235775 (192.168.1.255)
    broadcast2_int = 3232235967 (192.168.1.255)

    EX: 192.168.1.128/25
    Prefix length (CIDR): 25
    Host bits: 32 - 25 = 7
    Possible host addresses: 2^7 = 128
    Broadcast value: 128 - 1 = 127

    Network address: 192.168.1.128 & 255.255.255.128 = 192.168.1.128
    Network address: 192.168.1.128
    Subnet mask    : 255.255.255.128

    Broadcast address: 192.168.1.128 + 127 = 192.168.1.255

    



    network1_int >> 7 = 3221225472 (shifting right by 7 bits)
    network2_int >> 7 = 3221225472 (identical after shifting)

    """

    try:
        # Split CIDR blocks into IP address and subnet mask parts
        ip1, mask1 = cidr1.split("/")
        ip2, mask2 = cidr2.split("/")

        # Convert IP addresses to integers for comparison
        ip1_int = int(ipaddress.IPv4Address(ip1))  
        ip2_int = int(ipaddress.IPv4Address(ip2))

        # Calculate network addresses based on subnet masks
        network1_int = ip1_int & (2**32 - 2**(32 - int(mask1)))
        network2_int = ip2_int & (2**32 - 2**(32 - int(mask2)))

        # Check if network addresses match or if one is a subnet of the other
        return network1_int == network2_int or \
               (network1_int >> (32 - int(mask2)) == network2_int >> (32 - int(mask2))) or \
               (network2_int >> (32 - int(mask1)) == network1_int >> (32 - int(mask1)))

        """
        broadcast1_int = network1_int | (2**(32 - int(mask1)) - 1)
        broadcast2_int = network2_int | (2**(32 - int(mask2)) - 1)

        return (network1_int == network2_int) or \
               (network1_int >= network2_int and network1_int <= broadcast2_int) or \
               (network2_int >= network1_int and network2_int <= broadcast1_int)"""

    except Exception as e:
        print(f"Error: {e}")
        return False
    
def cidr_to_subnet(cidr):

    try:
        prefix_length = int(cidr.split('/')[1])
        """ It starts with 0xffffffff, which is 32 bits of all 1s (representing a full subnet mask).
        It shifts those bits right by (32 - prefix_length) positions, effectively setting those bits to 0s.
        It then shifts the result back left by the same amount, ensuring the 1s are contiguous at the beginning of the mask.

        Initial state: 1010
        First shift: 0101 (leftmost 1 shifted out, replaced with 0)
        Second shift: 0010 (leftmost 0 shifted out, replaced with 0) """

        subnet_mask = (0xffffffff >> (32 - prefix_length)) << (32 - prefix_length)
        subnet_mask_str = ".".join([str((subnet_mask >> i) & 0xff) for i in (24, 16, 8, 0)])
        return subnet_mask_str
    except (IndexError, ValueError):
        return None

def reverse_dns_lookup(ip_address):
    try:
        # Get hostnames associated with the IP address
        hostnames, _, _ = socket.gethostbyaddr(ip_address)

        # Return the first hostname
        return hostnames[0]

    except (socket.herror, socket.gaierror) as e:
        # Handle errors gracefully
        print("Error during reverse DNS lookup:", e)
        return None
    
def get_all_interface_ips():
    """Retrieves and displays IPv4 addresses for all available network interfaces."""

    print("IP addresses for all interfaces:")

    for interface_name in netifaces.interfaces():
        try:
            addresses = netifaces.ifaddresses(interface_name)
            ip_addresses = addresses.get(netifaces.AF_INET, [])

            if ip_addresses:
                print(f"\nInterface: {interface_name}")
                for ip_address in ip_addresses:
                    try:
                        hostname = socket.gethostbyaddr(ip_address['addr'])[0]
                        print(answers_color ,f"- IP Address: {ip_address['addr']} (Hostname: {hostname})")
                    except socket.herror:
                        print(answers_color ,f"- IP Address: {ip_address['addr']} (Hostname: Not found)")
            else:
                print(answers_color ,f"\nInterface '{interface_name}' has no IPv4 addresses.")

        except ValueError as e:
            print(answers_color ,f"Error fetching IP addresses for interface '{interface_name}': {e}")

# def list_interfaces():
#     """Lists network interfaces with their connection names, formatted for readability."""

#     interfaces = netifaces.interfaces()
#     count = 1
#     for interface in interfaces:
#         try:
#             addrs = netifaces.ifaddresses(interface)
#             iface_info = addrs[netifaces.AF_INET][0]
#             conn_name = iface_info['friendly']

#             print(f"{count}. Interface: {interface}")
#             print(f"   Connection Name: {conn_name}")
#             print()
#             count += 1

#         except KeyError:
#             # Handle interfaces without a friendly connection name
#             print(f"{count}. Interface: {interface}")
#             print(f"   Connection Name: (Not available)")
#             print()
#             count += 1

 
def scan_lan_devices(interface):
    """Scans the local area network (LAN) for active devices using Scapy.

    Args:
        interface (str): The name of the network interface to use for scanning.

    Returns:
        list: A list of discovered device IP addresses.
    """

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"), iface=interface, timeout=2)

    discovered_devices = []
    for snd, rcv in ans:
        device_ip = rcv[ARP].psrc
        discovered_devices.append(device_ip)

    return discovered_devices

if __name__ == "__main__":
    while True:
        print(questions_color + "Options:")
        print(questions_color + "1. Find class and separate network/host")
        print(questions_color + "2. Subnet IP address")
        print(questions_color + "3. Ipaddress Library")
        print(questions_color + "4. Exit")
        print(questions_color + "5. Check same network")
        print(questions_color + "6. Reverse Dns")
        print(questions_color + "7. Your Ip")
        print(questions_color + "8. List devices on interface" + Fore.RESET)




        choice = input("Enter your choice: ")
        if choice == "1":
            ip_input = get_valid_ip_address()
            
            # Is it CIDR or Class-based IP
            if "/" in ip_input:
                ip_parts = ip_input.split("/")
                ip_address = ip_parts[0]
                subnet_mask = int(ip_parts[1])
                network_address = ".".join([
                    bin(int(octet11, 2) & int(octet22, 2))[2:].zfill(8)
                    for octet11, octet22 in zip(*[octet.split(".") for octet in (ip_to_binary(ip_address), subnet_mask_to_binary(subnet_mask))])
                ])
                print(answers_color + "\nIP in binary:         ",answers_result_color + ip_to_binary(ip_address))
                print(answers_color + "Subnet mask in binary:",answers_result_color + subnet_mask_to_binary(subnet_mask))
                print(answers_color + "Network address      :",answers_result_color + network_address)
                subnet_mask = cidr_to_subnet(ip_input)
                if subnet_mask:
                    print(answers_color + "Subnet mask:",answers_result_color, subnet_mask)
                else:
                    print("Invalid CIDR notation")

                number_of_hosts = 2**(32 - int(ip_input.split('/')[1])) - 2
                print(answers_color + "Number of hosts      :",answers_result_color , number_of_hosts)

            else:
                ip_address = ip_input
                print(answers_color + "\nIP in binary:",answers_result_color + ip_to_binary(ip_address))
                subnet_mask = None
                separate(ip_address.split("."), find_class(ip_address.split(".")))

            
            ip_octets = ip_address.split(".")  # Split into a list of octets
            network_class = find_class(ip_octets)
            print(answers_color + "\nIP:",answers_result_color + ip_input)
            print(answers_color + "Given IP address belongs to class:",answers_result_color + network_class)
            
        
        elif choice == "2":
            ip_input = get_valid_ip_address()
            if "/" in ip_input:
                subnet(ip_input)
            else:
                cidr_input = input("No CIDR, add the CIDR: \t")
                if "/" in cidr_input:
                    subnet(ip_input+cidr_input)
                else:
                    subnet(ip_input+"/"+cidr_input)
                
        elif choice == "3":
            ip_input = input("Enter an IP address: ")

            print(answers_color + "Private: ", answers_result_color , ipaddress.ip_address(ip_input).is_private)
            print(answers_color + "Global: ", answers_result_color , ipaddress.ip_address(ip_input).is_global)
            print(answers_color + "Multicast: ", answers_result_color , ipaddress.ip_address(ip_input).is_multicast)
            print(answers_color + "Reserved: ", answers_result_color , ipaddress.ip_address(ip_input).is_reserved)
            
        elif choice == "4":
            break
        elif choice == "5":
            ip_input = get_valid_ip_address()
            ip_input2 = get_valid_ip_address()
            same_network = check_same_network(ip_input, ip_input2)
            if same_network:
                print(answers_color +"IP addresses are in the same network")
            else:
                print(answers_color +"IP addresses are not in the same network")
        elif choice == "6":
            ip_input = get_valid_ip_address()
            hostname = reverse_dns_lookup(ip_input)
            if hostname:
                print(answers_color + "Hostname:",answers_result_color , hostname)
            else:
                print(answers_color + "Reverse DNS lookup failed")
        elif choice == "7":
            get_all_interface_ips()
        elif choice == "8":
            addrs = psutil.net_if_addrs()

            # Print interface names with clear formatting
            for interface_name in addrs.keys():
                print(answers_color ,"-" * 20)  # Visual separator
                print(answers_result_color ,interface_name,Fore.RESET)

            addrs = psutil.net_if_addrs()
            interface_name = input("Enter the Interface name: ")
            devices = scan_lan_devices(interface_name)
            print("Discovered devices on interface", interface_name, ":")
            for device_ip in devices:
                print(answers_result_color ,"-", device_ip)
        else:
            print(questions_color + "Invalid choice. Please try again.")

        print()  # Print an empty line for separation
