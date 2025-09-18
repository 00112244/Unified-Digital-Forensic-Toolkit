import argparse
import os
import hashlib
from PIL import Image
from PIL.ExifTags import TAGS
from datetime import datetime
from colorama import Fore, Style
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def print_text_in_rectangle(text, text_color=Fore.GREEN):
    box_width = 90
    box_height = 4
    border_horizontal = f"{Fore.WHITE}+{'-' * (box_width - 2)}+{Style.RESET_ALL}"
    empty_line = f"{Fore.WHITE}|{' ' * (box_width - 2)}|{Style.RESET_ALL}"

    boxed_text = [border_horizontal] + [empty_line] * ((box_height - 2) // 2)
    boxed_text.extend(f"{Fore.WHITE}| {text_color}{Style.BRIGHT}{line.center(box_width - 4)}{Style.RESET_ALL} |{Style.RESET_ALL}" for line in text.splitlines())
    boxed_text.extend([empty_line] * ((box_height - 2) // 2) + [border_horizontal])

    return "\n".join(boxed_text)

def extract_metadata_and_gps(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()

        if exif_data:
            metadata = {}

            if 34853 in exif_data:
                gps_info = exif_data[34853]
                latitude_degrees = gps_info[2][0]
                latitude_minutes = gps_info[2][1]
                latitude_seconds = gps_info[2][2] / 100
                latitude_direction = "N" if gps_info[3] == "N" else "S"

                longitude_degrees = gps_info[4][0]
                longitude_minutes = gps_info[4][1]
                longitude_seconds = gps_info[4][2] / 100
                longitude_direction = "E" if gps_info[5] == "E" else "W"

                formatted_latitude = f"{latitude_degrees}° {latitude_minutes}' {latitude_seconds:.2f}\" {latitude_direction}"
                formatted_longitude = f"{longitude_degrees}° {longitude_minutes}' {longitude_seconds:.2f}\" {longitude_direction}"

                metadata['GPS Latitude'] = formatted_latitude
                metadata['GPS Longitude'] = formatted_longitude
            else:
                metadata['GPS Latitude'] = "N/A"
                metadata['GPS Longitude'] = "N/A"

            for tag, value in exif_data.items():
                tag_name = TAGS.get(tag, tag)
                metadata[tag_name] = value

            return metadata
        else:
            return None
    except (OSError, FileNotFoundError) as file_error:
        print(f"Error opening image file: {file_error}")
        return None
    except Exception as e:
        print(f"Error extracting metadata: {str(e)}")
        return None

def analyze_timestamp(metadata, reference_time):
    try:
        if 'DateTimeOriginal' in metadata:
            image_timestamp = datetime.strptime(metadata['DateTimeOriginal'], "%Y:%m:%d %H:%M:%S")
            time_difference = image_timestamp - reference_time
            return f"Time Difference: {time_difference}"
        else:
            return "DateTimeOriginal not found in metadata."
    except (ValueError, KeyError) as timestamp_error:
        print(f"Error analyzing timestamp: {timestamp_error}")
        return "Timestamp analysis failed."

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

def generate_pdf_report_with_metadata(metadata, script_location, welcome_message, case_info, evidence_info, md5_hash_output, sha256_hash_output):
    try:
        pdf_filename = os.path.join(script_location, 'image_analysis_report.pdf')
        doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
        content = []

        styles = getSampleStyleSheet()

        title = "Image Metadata Analysis Report"
        content.append(Paragraph(title, styles['Title']))

        content.append(Spacer(1, 30))
        content.append(Paragraph("Case Information:", styles['Heading3']))
        case_info_data = [
            ["Case ID", case_info['case_id']],
            ["Investigator Name", case_info['investigator_name']],
            ["Date Time", case_info['date_time']]
        ]
        case_info_table = Table(case_info_data, colWidths=[150, 300], repeatRows=1)
        content.append(case_info_table)
        content.append(Spacer(1, 1))

        content.append(Spacer(1, 10))
        content.append(Paragraph("Evidence Information:", styles['Heading3']))
        evidence_info_data = [
            ["Evidence ID", evidence_info['evidence_id']],
            ["Evidence Name", evidence_info['evidence_name']]
        ]
        evidence_info_table = Table(evidence_info_data, colWidths=[150, 300], repeatRows=1)
        content.append(evidence_info_table)
        content.append(Spacer(1, 1))

        content.append(Spacer(1, 15))
        content.append(Paragraph("Extracted Metadata:", styles['Heading3']))

        metadata_table_data = [['Content', 'Value'], *[[key, str(value)] for key, value in metadata.items()]]
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

        content.append(Spacer(1, 20))
        content.append(metadata_table)

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
    except Exception as report_error:
        print(f"Error generating PDF report: {report_error}")
        return None

def welcome_message():
    welcome_message = """
======================================================================================================================================================
                                                                Exif Explorer - Welcome
======================================================================================================================================================

Welcome to the Image Metadata Analysis Tool!

This powerful tool empowers you to delve into the intricate details of image files, providing comprehensive insights into their metadata. Whether you're a digital forensics investigator, a system administrator, or simply curious about the specifics of an image, this tool is tailored to meet your needs.

Key Features:
- Extracts detailed metadata from image files, including GPS information.
- Calculates MD5 and SHA256 hashes for integrity verification.
- Generates user-friendly reports in both text and PDF formats.
- Analyzes and presents timestamp information for forensic analysis.

Instructions:
1. Run the script with the path to the image file as a command-line argument.
2. Optional: Use flags (-i, -O, -r) to display information in the console, save output as a text file, and generate a PDF report, respectively.
3. Follow on-screen prompts to enter case and evidence details for inclusion in the report.

Note: Ensure dependencies (PIL, colorama, reportlab) are installed and permissions are granted for file access.

Thank you for choosing the Image Metadata Analysis Tool. Let the exploration of image data begin!
"""


    return(welcome_message)

def main():
    try:
        parser = argparse.ArgumentParser(description="Image Metadata Analysis Tool")
        parser.add_argument("image_path", nargs='?', help="Path to the image file to analyze")
        parser.add_argument("-r", "--report_file", action="store_true", help="Generate PDF report")
        parser.add_argument("-O", "--output_file", action="store_true", help="Save output as text file")
        parser.add_argument("-i", "--info", action="store_true", help="Display information in the console")

        args = parser.parse_args()

        reference_time = datetime.now()

        if args.image_path:
            metadata = extract_metadata_and_gps(args.image_path)

            md5_hash_output = None
            sha256_hash_output = None

            if metadata is not None:
                if args.output_file:
                    output_file_path = 'output.txt'
                    with open(output_file_path, 'w', encoding='utf-8') as file:
                        for key, value in metadata.items():
                            file.write(f"{key}: {value}\n")
                    print("Output saved successfully to", output_file_path)
                    md5_hash_output = generate_md5_hash(output_file_path)
                    sha256_hash_output = generate_sha256_hash(output_file_path)

                if args.info:
                    print("\nImage Metadata:")
                    for key, value in metadata.items():
                        print(f"{key}: {value}")

                    timestamp_analysis = analyze_timestamp(metadata, reference_time)
                    print("\nTimestamp Analysis:")
                    print(timestamp_analysis)

                if args.report_file:
                    case_info_data = {
                        'case_id': input("Enter Case ID: "),
                        'investigator_name': input("Enter Investigator Name: "),
                        'date_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    evidence_info_data = {
                        'evidence_id': input("Enter Evidence ID: "),
                        'evidence_name': input("Enter Evidence Name: ")
                    }

                    pdf_filename = generate_pdf_report_with_metadata(metadata, os.path.dirname(os.path.abspath(__file__)),
                                                                     welcome_message(), case_info_data, evidence_info_data,
                                                                     md5_hash_output, sha256_hash_output)

                    if not args.output_file and not args.report_file and not args.info:
                        print("\nImage Metadata:")
                        for key, value in metadata.items():
                            print(f"{key}: {value}")

                        timestamp_analysis = analyze_timestamp(metadata, reference_time)
                        print("\nTimestamp Analysis:")
                        print(timestamp_analysis)

    except Exception as main_error:
        print(f"An unexpected error occurred: {main_error}")

if __name__ == "__main__":
    welcome_message()
    main()

#commands
#python data.py C:\Users\thiru\exif-samples\jpg\Canon_40D_photoshop_import.jpg -i (display output in console)
#python data.py C:\Users\thiru\exif-samples\jpg\Canon_40D_photoshop_import.jpg -O (save output in txt)
#python data.py C:\Users\thiru\exif-samples\jpg\Canon_40D_photoshop_import.jpg -r -O (pdf report and output txt)