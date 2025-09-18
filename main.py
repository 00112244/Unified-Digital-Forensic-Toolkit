import sys
import subprocess
import argparse
from pyfiglet import Figlet
from termcolor import colored

def display_colored_text_in_style(text, font_style, width, color):
    try:
        fig = Figlet(font=font_style, width=width)
        ascii_art = fig.renderText(text)
        colored_art = colored(ascii_art, color)
        print(colored_art)
    except Exception as e:
        print(f"Error displaying colored text: {e}")

def run_tool(tool_script):
    try:
        welcome_message_func = getattr(__import__(tool_script.replace('.py', '')), 'welcome_message', None)
        
        if welcome_message_func:
            print(welcome_message_func())

        if tool_script == "net.py":
            # Print the net_message for NetPulse Analyzer
            net_message = """
======================================================================================================================================================
                                            🚀 NetPulse Analyzer - Real-Time Network Traffic Analysis 🚀
======================================================================================================================================================

Key Features:

1. Real-Time Packet Capture: Capture live network packets using Scapy.

2. Packet Details Table: Explore packet details - IP, protocol, timestamp.

3. Traffic Distribution Chart: Visualize network traffic distribution by protocols.

4. Traffic Trend Over Time: Track trends in network traffic with an interactive chart.

5. Packet Details View: Inspect individual packets with frame, summary, byte details, and tree view.

How to Use:
1. Launch PacketAnalyzer for real-time packet capture.
2. Explore the Packet Details Table for insights into captured packets.
3. Analyze the Traffic Distribution Chart to identify common protocols.
4. Use the Traffic Trend Chart to understand variations over time.
5. Click on a packet in the table for detailed information in the Packet Details View.

Analyze, troubleshoot, and gain insights into your network traffic effortlessly! 


Thank you for choosing NetPulseAnalyzer! If you have any feedback or questions, feel free to reach out. Happy analyzing!
"""
            print(net_message)

        
            try:
               # Directly run the entire network script without asking for input
               subprocess.run(["python", tool_script])
            except KeyboardInterrupt:
                print("\nStopping the script...")
        else:  
            # For other tools, prompt for input
            parser = argparse.ArgumentParser()
            subprocess_args = input(f"Enter the input and option for {tool_script} (space-separated): ")
            subprocess_args = subprocess_args.split()

            subprocess.run(["python", tool_script] + subprocess_args)
    except ImportError:
        print("Error: Could not import the tool script.")
    except subprocess.CalledProcessError as e:
        print(f"Error running the tool: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def print_menu():
    print("Forensic Toolkit Menu:")
    print("1. Email Header Analyzer")
    print("2. FileFusionizer")
    print("3. Exif Explorer")
    print("4. URL Guardian")
    print("5. NetPulse Analyzer")
    print("6. Exit")

def main():
    try:
        # Set your desired text, font style, width, and color
        text = "Unified Digital Forensics Toolkit \n (UFED)"
        font_style = "big" #xsbook #xsbookbi #big
        width = 200
        color = "cyan" 

        display_colored_text_in_style(text, font_style, width, color)
     
        message = """
************************************************************************************************************************************************************
                                                            Welcome to the Forensic Explorer Toolkit
************************************************************************************************************************************************************
        
This toolkit provides a set of powerful tools for digital forensics,
allowing you to analyze and extract valuable information from various sources.

Tools available in the toolkit:
1. Email Header Analyzer: Extract and analyze email headers for forensic investigations.
2. FileFusionizer: Analyze and process files for forensic examination and data fusion.
3. Exif Explorer: Explore and extract metadata from image files for forensic analysis.
4. URL Guardian: Analyze and extract information from URLs whether for investigative purposes.
5. NetPulse Analyzer: Real-time network packet analysis with interactive visualizations and detailed packet inspection. 

Usage:
    - Select a tool by entering the corresponding number.
    - Follow the prompts to provide necessary inputs for the selected tool.
    - After using a tool, decide whether to exit and return to the main menu.

Note: Each tool is designed to assist in specific aspects of digital forensics.
      Feel free to explore and utilize these tools for your investigative needs!
      Ensure you have the required dependencies installed and proper permissions to access the specified files and folders.
        """
        print(message) 

        while True:
            print_menu()
            choice = input("Select a tool (1-6): ")

            if choice == "6":
                print("Exiting the Forensic Toolkit.")
                break

            elif choice in ["1", "2", "3", "4","5"]:
                if choice == "1":
                    tool_script = "email_header.py"
                elif choice == "2":
                    tool_script = "file.py"
                elif choice == "3":
                    tool_script = "metadata.py"
                elif choice == "4":
                    tool_script = "url.py"
                elif choice == "5":
                    tool_script = "net.py"
                else:
                    print("Invalid choice. Please enter a valid option.")
                    continue

                while True:
                        run_tool(tool_script)
                        exit_tool = input("Do you want to exit this tool and go back to the main menu? (yes/no): ").lower()
                        if exit_tool == "yes":
                           break   
            else:
                print("Invalid choice. Please enter a valid option.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
