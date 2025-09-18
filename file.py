import os
import argparse
import magic
import mmap
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# Initialize styles globally
styles = getSampleStyleSheet()

metadata = {}

# Update the file_signatures dictionary
file_signatures = {
    'JPEG': (b'\xFF\xD8\xFF\xE0', 0),
    'PDF': (b'%PDF-', 0),
    'PNG': (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 0),
    'DOCX': (b'PK\x03\x04', 0),
    'XLSX': (b'PK\x03\x04', 0),
    'MP3': (b'\xFF\xFB', 0),
    'ZIP': (b'PK\x03\x04', 0),
    'GIF': (b'GIF87a', 0),
    'TEXT': (b'', 0),  # For TXT files, no specific magic number
    'PPTX': (b'PK\x03\x04', 0),
    'CSV': (b'', 0),  # For CSV, no specific magic number
    'EXE': (b'MZ', 0),
    'JSON': (b'', 0),  # For JSON, no specific magic number
    'HTML': (b'', 0),  # For HTML, no specific magic number
    'XML': (b'<?xml', 0)
    # Add more file signatures and corresponding file types as needed
}

# Update the file_extension_mapping dictionary
file_extension_mapping = {
    'JPEG': ['.jpg', '.jpeg'],
    'PDF': ['.pdf'],
    'PNG': ['.png'],
    'DOCX': ['.docx'],
    'XLSX': ['.xlsx'],
    'MP3': ['.mp3'],
    'ZIP': ['.zip'],
    'GIF': ['.gif'],
    'TEXT': ['.txt'],
    'PPTX': ['.pptx'],
    'CSV': ['.csv'],
    'EXE': ['.exe'],
    'JSON': ['.json'],
    'HTML': ['.html', '.htm'],
    'XML': ['.xml']
    # Add more file extensions for each file type
}


def identify_file_type(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Map the file to memory for efficient reading
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                for file_type, (signature, offset) in file_signatures.items():
                    if mmapped_file[offset:offset + len(signature)] == signature:
                        return file_type
    except Exception as e:
        return f'Error: {str(e)}'

    return 'Unknown File Type'


def calculate_file_hash(file_path):
    hash_algorithms = ['md5', 'sha1', 'sha256']
    hash_output = ""

    try:
        with open(file_path, 'rb') as file:
            for algorithm in hash_algorithms:
                hash_obj = hashlib.new(algorithm)
                for chunk in iter(lambda: file.read(4096), b''):
                    hash_obj.update(chunk)
                hash_value = hash_obj.hexdigest()
                hash_output += f'{algorithm.upper()}: {hash_value}\n\n\n'
    except Exception as e:
        hash_output = f'Error: {str(e)}'

    return hash_output.strip()  # Remove trailing newline before returning


def extract_file_metadata(file_path):

    try:
        metadata['File Name'] = os.path.basename(file_path)
        metadata['File Size (bytes)'] = os.path.getsize(file_path)
        metadata['File Type (Magic)'] = magic.Magic(mime=True).from_file(file_path)

        # Identify file type using signature analysis
        file_type = identify_file_type(file_path)
        metadata['File Type (Advanced)'] = file_type

        # File type extension mapping
        if file_type in file_extension_mapping:
            metadata['File Extensions'] = file_extension_mapping[file_type]

        # Calculate file hashes
        metadata['File Hashes'] = calculate_file_hash(file_path)

        stat_info = os.stat(file_path)
        # Convert Unix timestamps to human-readable format
        metadata['Creation Time'] = datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['Modification Time'] = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['Access Time'] = datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S')
        permissions = oct(stat_info.st_mode & 0o777)
        metadata['Permissions'] = permissions
        metadata['File Path'] = os.path.abspath(file_path)
    except Exception as e:
        metadata['Error'] = str(e)

    return metadata


def process_file(file_path):
    metadata = extract_file_metadata(file_path)


def process_folder(folder_path):
    files_to_process = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            files_to_process.append(os.path.join(root, file))
    return files_to_process


def generate_pdf_report(metadata, script_location, welcome_message, case_info, evidence_info, output_path, md5_hash_output,
                        sha256_hash_output):
    pdf_filename = os.path.join(script_location, 'file_analysis_report.pdf')

    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    content = []

    # Add a title to the PDF
    title = "File Metadata Analysis Report"
    content.append(Paragraph(title, styles['Title']))
 # Case Information
    content.append(Spacer(1, 10))
    content.append(Paragraph("Case Information:", styles['Heading3']))
    case_info_data = [
        ["Case ID", case_info['case_id']],
        ["Investigator Name", case_info['investigator_name']],
        ["Date Time", case_info['date_time']]
    ]
    case_info_table = Table(case_info_data, colWidths=[150, 300], repeatRows=1)
    content.append(case_info_table)
    content.append(Spacer(1, 1))

    # Evidence Information
    content.append(Spacer(1, 10))
    content.append(Paragraph("Evidence Information:", styles['Heading3']))
    evidence_info_data = [
        ["Evidence ID", evidence_info['evidence_id']],
        ["Evidence Name", evidence_info['evidence_name']]
    ]
    evidence_info_table = Table(evidence_info_data, colWidths=[150, 300], repeatRows=1)
    content.append(evidence_info_table)
    content.append(Spacer(1, 1))  # Adjust the spacing between the evidence info and the next section

    # Add metadata to PDF content as a table
    content.append(Spacer(1, 10))
    content.append(Paragraph("File Metadata:", styles['Heading2']))

    # Create a table for metadata
    metadata_table_data = [
        ["Content", "Value"],
        *[[key, str(value)] for key, value in metadata.items()]  # Convert values to strings for proper display
    ]
    metadata_table = Table(metadata_table_data, colWidths=[150, 300], repeatRows=1)
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    # Add metadata table to content
    content.append(metadata_table)

    # Add MD5 hash information to the content
    if md5_hash_output:
        md5_heading_text = "MD5 Hash of Output File: "
        md5_text = f"<font name='Helvetica-Bold'>{md5_heading_text}</font>{md5_hash_output}"
        md5_paragraph = Paragraph(md5_text, styles['Normal'])
        content.append(Spacer(1, 30))
        content.append(md5_paragraph)

    # Add SHA256 hash information to the content
    if sha256_hash_output:
        sha256_heading_text = "SHA256 Hash of Output File: "
        sha256_text = f"<font name='Helvetica-Bold'>{sha256_heading_text}</font>{sha256_hash_output}"
        sha256_paragraph = Paragraph(sha256_text, styles['Normal'])
        content.append(Spacer(1, 20))
        content.append(sha256_paragraph)

    # Build the PDF document
    doc.build(content)

    print(f"PDF report generated successfully: {pdf_filename}")
    print(f"MD5 Hash of the Output File: {md5_hash_output}")
    print(f"SHA256 Hash of the Output File: {sha256_hash_output}")
    return pdf_filename



def generate_md5_hash(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


def generate_sha256_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def welcome_message():
    # Define welcome_message
    welcome_message = """
======================================================================================================================================================
                                                        Welcome To FileFusionizer
======================================================================================================================================================

This script is designed to analyze the metadata of files and folders, providing valuable insights into various attributes of the specified data. Whether you are a digital forensics investigator, a system administrator, or simply curious about file details, this tool can assist you in extracting and documenting relevant information.

Key Features:
- Extracts metadata such as file size, creation/modification dates, and more.
- Supports analysis of individual files or entire folders.
- Generates JSON reports for easy data storage and sharing.
- Optionally creates a PDF report for comprehensive documentation.

Instructions:
1. Run the script with the -f/--file argument followed by the path to the file you want to analyze.
2. Choose optional features like saving metadata to a JSON file or generating a PDF report.
3. Follow on-screen prompts for additional information, such as case and evidence details.
4. Review the generated reports for a comprehensive overview of the analyzed data.


Thank you for choosing FileFusionizer. Let's begin the analysis!
"""

  
    return(welcome_message)

def main():
    try:
        parser = argparse.ArgumentParser(description='File Metadata Analysis Script')
        parser.add_argument('-f', '--file', required=True, help='Path to the file for analysis')
        parser.add_argument('-o', '--output', action='store_true', help='Save output to a JSON file')
        parser.add_argument('-r', '--report_file', action='store_true', help='Generate PDF report')

        args = parser.parse_args()

        file_path = args.file

        if os.path.exists(file_path):
            if os.path.isfile(file_path):
                process_file(file_path)

                if not args.output and not args.report_file:
                    for key, value in metadata.items():
                        print(f"{key}: {value}")
            else:
                print("Error: The specified path is not a file.")
        else:
            print(f"Error: The specified path '{file_path}' does not exist.")

        if args.output:
            output_path = 'output.json'
            with open(output_path, 'w') as outfile:
                json.dump(metadata, outfile, indent=4)
            print(f'File metadata saved to: {output_path}')

        if args.output and args.report_file:
            md5_hash_output = generate_md5_hash(output_path)
            sha256_hash_output = generate_sha256_hash(output_path)

            case_info = {
                'case_id': input("Enter Case ID: "),
                'investigator_name': input("Enter Investigator Name: "),
                'date_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            evidence_info = {
                'evidence_id': input("Enter Evidence ID: "),
                'evidence_name': input("Enter Evidence Name: ")
            }
            pdf_filename = generate_pdf_report(metadata, os.path.dirname(os.path.abspath(__file__)), welcome_message(),
                                   case_info, evidence_info, output_path, md5_hash_output,
                                   sha256_hash_output)

    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()

#commands:
    #python files.py -r -o (generate report and save output as JSON)
    #python files.py -o  ( save output as JSON)
    #python files.py (display output in console)    