#!/usr/bin/env python3
import subprocess
import datetime
import os
import re
import time


####################################################################
####################################################################
####################################################################
#sub-domain enumerator

def enumerate_domain():
    print("---------------------")
    domain = input("Enter the target domain (e.g., example.com): ")
    print("---------------------")
    #-------recon-ng
    recon_output_file = f"recon_{domain.replace('.', '_')}.txt"
    run_recon_cli(domain, recon_output_file)
    #-------subfinder
    subfinder_output_file = f"subfinder_{domain.replace('.','_')}.txt"
    run_command_subfinder(domain, subfinder_output_file)


def run_recon_cli(domain, output_file):
    workspace_name = domain.replace('.', '_')
    print(f"For recon-ng results will be saved to: {output_file}")
    command = [
        "recon-cli",
        "-w", workspace_name,
        "-m", "recon/domains-hosts/hackertarget",
        "-o", f"SOURCE={domain}",
        "-x"
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        # Write output to file
        with open(output_file, 'w') as f:
            f.write(f"=== Recon-CLI Subdomain Scan for {domain} ===\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Command: {' '.join(command)}\n\n")
            f.write("=== STDOUT ===\n")
            f.write(stdout)
            f.write("\n=== STDERR ===\n")
            f.write(stderr)
        
        # Check for successful execution
        if process.returncode != 0:
            print(f"Scan encountered errors (code: {process.returncode}). Check {output_file} for details.")
        
        return process.returncode
        
    except Exception as e:
        print(f"Error executing command: {e}")
        with open(output_file, 'w') as f:
            f.write(f"Error executing command: {e}\n")
        return 1


def run_command_subfinder(domain, subfinder_output):    
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Write output to file
        with open(subfinder_output, 'w') as f:
            f.write(result.stdout)
        
        # print(f"Subfinder scan completed successfully!")
        print(f"Results saved to: {os.path.abspath(subfinder_output)}")
        return subfinder_output
        
    except subprocess.CalledProcessError as e:
        print(f"Error running subfinder: {e}")
        print(f"Error output: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")





#############################################
#############################################
#############################################
#nmap_domain_scanner

def nmap_domain_scanner():
    print("Subdomain Port Scanner")
    print("======================")
    
    # Get recon-ng output file from user
    recon_file = input("Enter the path to your recon-ng output file which has enumerated domain name: ")
    if not recon_file:
        print("Not found")
        main()
    
    # Extract targets
    domain = extract_data_from_recon_file(recon_file,"recon_extracted.txt")
    print("---------------------")
    output_file = input("Enter the path to save scan results ")
    print("---------------------")
    command_recon = "sudo nmap -iL recon_extracted.txt"
    run_command_and_save(command_recon,output_file)
    #subfinder
    print("---------------------")
    subfinder_output = input("Enter the path for your subfinder file which has enumerated domain name")
    print("---------------------")
    if not subfinder_output:
        print("not found")
        main()
    command = f"sudo nmap -iL {subfinder_output}"
    output = f"{subfinder_output}_nmap.txt"
    run_command_and_save(command,output)








def run_command_and_save(command,output_file):
    """
    Run a Linux command based on user input and save its output to a text file.
    Takes command and output filename from user input.
    """
    try:
        # Get command from user
        #command = input("Enter the command to execute: ")
        
        # Get output file name from user
        #output_file = input("Enter the output file name: ")
        
        print(f"Executing: {command}")
        print(f"Saving output to: {output_file}")
        
        # Execute the command and capture output
        result = subprocess.run(
            command,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Write output to file
        with open(output_file, 'w') as f:
            # Write stdout
            f.write("=== STDOUT ===\n")
            f.write(result.stdout)
            
            # Write stderr if there's any
            if result.stderr:
                f.write("\n=== STDERR ===\n")
                f.write(result.stderr)
            
            # Write return code
            f.write(f"\n=== RETURN CODE ===\n{result.returncode}")
        
        print(f"Command executed. Output saved to {output_file}")
        return result.returncode
            
    except Exception as e:
        print(f"Error: {e}")
        return 1







############################################################
############################################################
#nuclei


def nuclei():
    #########################
    ##########################
    ##########################
    #recon output
    print("---------------------")
    recon_file = input("Enter the path to your recon-ng output file: ")
    print("---------------------")
    # Extract targets
    domain = extract_data_from_recon_file(recon_file,"recon_file.txt")
    output_recon = f"recon_nuclei_scan_{domain}.txt"
    # run_command("/usr/bin/httpx -l recon_file.txt -silent -o temp1.txt > /dev/null 2>&1")
    run_command(f"nuclei -l recon_file.txt -o {output_recon}")


    ################################
    ################################
    ################################
    #for subfinder

        
    output_subfinder = f"subfinder_nuclei_scan_{domain}.txt"
    output_domain_subfinder = input("Enter the domain enumrated file for subfinder ")
    # run_command("/usr/bin/httpx -l subfinder.txt -silent -o temp2.txt > /dev/null 2>&1")
    run_command(f"nuclei -l {output_domain_subfinder} -o {output_subfinder}")

def run_command(command):
    """
    Execute a command directly without filtering
    
    Args:
        command (str): The command to execute
    """
    try:
        # Execute the command
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        # for line in process.stdout:
        #     print(line, end='')
            
        # Wait for process to complete
        process.wait()
        
    except Exception as e:
        print(f"Error: {e}")

















def extract_data_from_recon_file(input_file,output_file):
    try:
        # Read the input file
        print(f"Reading file: {input_file}")
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Extract domain from header
        domain_match = re.search(r'-+\s*([A-Za-z0-9.-]+)\s*-+', content)
        main_domain = domain_match.group(1).lower() if domain_match else "unknown_domain"
        print(f"Detected domain: {main_domain}")
        
        # Extract host names
        # Pattern looks for Host: followed by the hostname
        pattern = r'Host: ([A-Za-z0-9.-]+)'
        matches = re.findall(pattern, content)
        
        print(f"Found {len(matches)} subdomains")
        
        # Write results to output file - one subdomain per line
        with open(output_file, 'w') as f:
            for host in matches:
                f.write(f"{host}\n")
        
        print(f"Successfully extracted {len(matches)} subdomains.")
        print(f"Results saved to: {output_file}")
        return main_domain
        
    except Exception as e:
        print(f"Error processing file: {e}")
        return False













def main():
    print("---------------------")
    print("---------------------")
    print("---------------------")
    print("We poke holes so the bad guys don’t have to!")
    print("---------------------")
    print("---------------------")
    print("---------------------")
    print("------MAIN MENU------")
    print("1. Enumerates domain")
    print("2. Scan all the listed domains with nmap")
    print("3. Scan the domains with nuclei")
    print("4. Scan the domains for SSL")
    print("5. Exit")
    print("----------------------------")
    print("Enter your choice")
    n = int(input())
    if(n==1):
        print("--------------------")
        print("--------------------")
        print("Crawling the web of your empire, one sneaky subdomain at a time")
        print("--------------------")
        print("--------------------")
        print("Lets first download the requirements ")
        run_command("sudo apt install subfinder")
        run_command("sudo apt install recon-ng")
        enumerate_domain()
        main()
    elif(n==2):
        print("--------------------")
        print("--------------------")
        print("Lock up your ports — we’re here to party with your packets!")
        print("--------------------")
        print("--------------------")
        print("Lets first download the requirements ")
        run_command("sudo apt install nmap")
        nmap_domain_scanner()
        main()
    elif(n==3):
        print("--------------------")
        print("--------------------")
        print("When Nuclei scans, vulnerabilities don’t stand a chance!")
        print("--------------------")
        print("--------------------")
        print("Lets first download the requirements ")
        run_command("sudo apt install nuclei")
        nuclei()
        main()
    elif(n==4):
        print("--------------------")
        print("--------------------")
        output_sslscan = input("Enter the output to subfinder domain enumerated file")
        command = f'sslscan --targets="{output_sslscan}"'
        run_command_and_save(command,"sslscan_subfinder")
        main()
    elif(n==5):
        print("program ended")
    else:
        print("Invalid")

    ####################
    ####################
    ####################

if __name__ == "__main__":
    print("------THIS IS A AUTOMATED TESTING TOOL------")
    main()