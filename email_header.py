import argparse
from datetime import datetime
import socket
import os
import hashlib
from tabulate import tabulate
from colorama import Fore, Style
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def print_highlighted_text(text):
    box_width = 80
    print("+" + "-" * (box_width - 2) + "+")
    for line in text.splitlines():
        print("|" + line.center(box_width - 2) + "|")
    print("+" + "-" * (box_width - 2) + "+")

def parse_header(header_file):
    try:
        with open(header_file, 'r') as file:
            lines = file.readlines()

        header_data = {}
        current_field = None
        current_value = ''

        for line in lines:
            if ':' in line:
                if current_field:
                    header_data[current_field] = current_value.strip()

                current_field, current_value = line.split(':', 1)
                current_field = current_field.strip()
                current_value = current_value.strip()
            elif current_field:
                current_value += ' ' + line.strip()

        if current_field:
            header_data[current_field] = current_value.strip()

        return header_data
    except FileNotFoundError:
        print(f"Error: Header file '{header_file}' not found.")
        return None
    except Exception as e:
        print(f"Error parsing header file: {str(e)}")
        return None

def display_header_info(header_data):
    try:
        output = ''
        additional_fields = {
            'Message-ID': 'Message ID',
            'Return-Path': 'Return Path',
            'Reply-To': 'Reply-To',
            'X-Headers': 'X-Headers',
            'Received': 'Received',
            'MIME-Version': 'MIME Version',
            'Content-Type': 'Content Type',
            'Received-SPF': 'Received-SPF',
            'DKIM-Signature': 'DKIM Signature',
            'Authentication-Results': 'Authentication Results',
            'X-Mailer': 'X-Mailer',
            'DMARC-Results': 'DMARC Results'
        }

        # Display message information
        output += f"{Fore.RED}Message Information:\n"
        output += "---------------------\n"
        output += Style.RESET_ALL

        # Commonly recognized email header fields
        fields = ['To', 'From', 'Subject', 'Date', 'Delivered-To']

        table_data = [[field, header_data.get(field, '')] for field in fields if field in header_data]

        output += tabulate(table_data, headers=[f"{Fore.BLUE}Field", f"{Fore.BLUE}Value"], tablefmt="fancy_grid")
        output += f"\n{Style.RESET_ALL}"

        # Display additional fields
        output += f"{Fore.RED}\nAdditional Fields:\n"
        output += "------------------\n"
        output += Style.RESET_ALL

        table_data = [[label, header_data.get(field, '')] for field, label in additional_fields.items() if field in header_data]
        output += tabulate(table_data, headers=[f"{Fore.BLUE}Field", f"{Fore.BLUE}Value"], tablefmt="fancy_grid")
        output += f"\n{Style.RESET_ALL}"

        return output, additional_fields
    except Exception as e:
        print(f"Error displaying header information: {str(e)}")
        return None, None

def get_dns_info(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        print(f"Error getting DNS information: {str(e)}")
        return None

def generate_pdf_report(header_data, md5_hash_output, sha256_hash_output):
    try:
        styles = getSampleStyleSheet()
        pdf_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'analysis_report.pdf')
        doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
        content = []

        title = "Email Header Analysis Report"
        content.append(Paragraph(title, styles['Title']))

        welcome_message_style = ParagraphStyle(
            'WelcomeMessage',
            parent=styles['Normal'],
            fontSize=13
        )

        content.append(Spacer(1, 30))
        content.append(Spacer(1, 10))
        welcome_message = """
        Welcome to Email Header Analyzer Tool!
        This tool is designed to extract and analyze email headers.
        It can help you extract sender, recipient, timestamps, \n and routing data from email headers.
        """
        welcome_message_paragraph = Paragraph(welcome_message, welcome_message_style)
        content.append(welcome_message_paragraph)

        content.append(Spacer(1, 30))
        content.append(Paragraph("Case Information:", styles['Heading3']))
        case_info_data = [
            ["Case ID", input("Enter Case ID: ")],
            ["Investigator Name", input("Enter Investigator Name: ")],
            ["Date Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        case_info_table = Table(case_info_data, colWidths=[150, 300], repeatRows=1)
        content.append(case_info_table)
        content.append(Spacer(1, 1))

        content.append(Spacer(1, 10))
        content.append(Paragraph("Evidence Information:", styles['Heading3']))
        evidence_info_data = [
            ["Evidence ID", input("Enter Evidence ID: ")],
            ["Evidence Name", input("Enter Evidence Name: ")]
        ]
        evidence_info_table = Table(evidence_info_data, colWidths=[150, 300], repeatRows=1)
        content.append(evidence_info_table)
        content.append(Spacer(1, 1))

        content.append(Spacer(1, 15))
        content.append(Paragraph("Message Information:", styles['Heading3']))

        fields = ['To', 'From', 'Subject', 'Date', 'Delivered-To']
        table_data = [[field, header_data.get(field, '')] for field in fields]
        table = Table(table_data, colWidths=[100, 300], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(Spacer(1, 20))
        content.append(table)

        if md5_hash_output:
            md5_heading_text = "MD5 Hash of Output File: "
            md5_text = f"<font name='Helvetica-Bold'>{md5_heading_text}</font>{md5_hash_output}"
            md5_paragraph = Paragraph(md5_text, styles['Normal'])
            content.append(Spacer(1, 30))
            content.append(md5_paragraph)

        if sha256_hash_output:
            sha256_heading_text = "SHA256 Hash of Output File: "
            sha256_text = f"<font name='Helvetica-Bold'>{sha256_heading_text}</font>{sha256_hash_output}"
            sha256_paragraph = Paragraph(sha256_text, styles['Normal'])
            content.append(Spacer(1, 20))
            content.append(sha256_paragraph)

        doc.build(content)

        print(f"PDF report generated successfully: {pdf_filename}")
        print(f"MD5 Hash of the Output File: {md5_hash_output}")
        print(f"SHA256 Hash of the Output File: {sha256_hash_output}")
        return pdf_filename
    except Exception as e:
        print(f"Error generating PDF report: {str(e)}")
        return None

def generate_md5_hash(output_file_path):
    try:
        md5_hash = hashlib.md5()
        with open(output_file_path, 'rb') as file:
            md5_hash.update(file.read())
        return md5_hash.hexdigest()
    except Exception as e:
        print(f"Error generating MD5 hash: {str(e)}")
        return None

def generate_sha256_hash(output_file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(output_file_path, 'rb') as file:
            sha256_hash.update(file.read())
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error generating SHA256 hash: {str(e)}")
        return None

def welcome_message():
    welcome_message = """
    Welcome to Email Header Analyzer Tool!
    This tool is designed to extract and analyze email headers.
    It can help you extract sender, recipient, timestamps, \n and routing data from email headers.
    """
    message = """"
    This powerful tool is designed to unravel the mysteries concealed within email headers. 
    Whether you're an investigator, security professional, or simply curious about the origins of an email, this tool provides valuable insights into sender details, recipients, timestamps, and routing information.

    Key Features:
    - Extract and Analyze Email Headers
    - Generate Detailed PDF Reports
    - Save Output to Text Files
    - Calculate MD5 and SHA256 Hash Values of Output file.

    How to Use:
    - Specify the path to the email header file using the '-hf' option.
    - Choose to generate a PDF report with '-r'.
    - Save the output to a text file using '-O'.


    Thank you for choosing the Email Header Analyzer Tool. Let's dive into the fascinating world of email headers and uncover the hidden details!
"""
    print_highlighted_text(welcome_message)
    print(message)

def main():
    try:
        parser = argparse.ArgumentParser(description='HeaderSpy', prog='har.py')
        parser.add_argument('-hf', '--header_file', type=str, help='Path to the email header file')
        parser.add_argument('-r', '--report_file', action='store_true', help='Generate PDF report')
        parser.add_argument('-O', '--output_file', action='store_true', help='Save output as text file')

        # Parse command-line arguments
        args = parser.parse_args()

        # Print welcome message
        welcome_message()

        # Parse email header file and display information
        header_file = args.header_file
        if not header_file:
            raise ValueError("Header file path is required.")

        header_data = parse_header(header_file)
        if not header_data:
            return

        output, additional_fields = display_header_info(header_data)

        # Display DNS information for 'From' field
        from_field = header_data.get('From', '')
        if from_field:
            email_parts = from_field.split('@')[-1]  # Extracting the domain part from the email address
            if len(email_parts) == 2:
                domain = email_parts[1]

                ip_address = get_dns_info(domain)
                additional_fields['DNS Information'] = ip_address
            print(f"DNS Information for 'From' Field ({from_field}): {get_dns_info(from_field)}")

        # Save the output to a file or print it to the console
        output_file = args.output_file
        if output_file:
            output_file_path = 'output.txt'
            with open(output_file_path, 'w', encoding='utf-8') as file:
                file.write(output)
            print("Output saved successfully.")

            # Generate MD5 hash of the output text file
            md5_hash_output = generate_md5_hash(output_file_path)

            # Generate SHA256 hash of the output text file
            sha256_hash_output = generate_sha256_hash(output_file_path)
        else:
            md5_hash_output = None
            sha256_hash_output = None

        # Generate PDF report if specified
        report_file = args.report_file
        if report_file:
            pdf_filename = generate_pdf_report(header_data, md5_hash_output, sha256_hash_output)
            if not pdf_filename:
                return
        elif not output_file:
            print(output)

    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()


#commands
#python har.py -hf D:\py\email_header\screen.txt  -O
#python har.py -hf D:\py\email_header\screen.txt -r -O
#python har.py -hf D:\py\email_header\screen.txt

