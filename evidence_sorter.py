"""
Digital Forensics Evidence Sorter
This program scans an evidence folder, categorizes files by type,
and generates a summary report of findings.
"""

import os
import shutil
import struct
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

# Path to the evidence folder to scan
EVIDENCE_FOLDER = "evidence"

# Path where categorized folders will be created
OUTPUT_FOLDER = "evidence_sorted"

# Define file categories and their extensions
FILE_CATEGORIES = {
    "network_captures": {
        "extensions": [".pcap", ".pcapng", ".cap"],
        "description": "Network capture files (packet analysis)"
    },
    "images": {
        "extensions": [".png", ".jpg", ".jpeg", ".gif", ".bmp"],
        "description": "Image files (pictures, screenshots)"
    },
    "documents": {
        "extensions": [".pdf", ".doc", ".docx", ".txt"],
        "description": "Document files (text, PDF)"
    },
    "archives": {
        "extensions": [".zip", ".rar", ".7z", ".tar", ".gz"],
        "description": "Archive/compressed files"
    },
    "unknown": {
        "extensions": [],
        "description": "Files with unknown or unsupported types"
    }
}

# List of suspicious file patterns to flag
SUSPICIOUS_PATTERNS = [
    "confidential",
    "secret",
    "private",
    "encrypted",
    "attack",
    "exploit",
]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_file_extension(filename):
    """Extract file extension in lowercase."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def categorize_file(filename, extension):
    """
    Determine which category a file belongs to based on extension.
    Returns the category name (string).
    """
    # Check each category
    for category, details in FILE_CATEGORIES.items():
        if extension in details["extensions"]:
            return category
    
    # If no match found, return unknown
    return "unknown"


def is_file_suspicious(filename):
    """
    Check if filename contains suspicious keywords.
    Returns True if suspicious pattern is found.
    """
    filename_lower = filename.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in filename_lower:
            return True
    return False


def get_file_size(filepath):
    """Get file size in bytes."""
    try:
        return os.path.getsize(filepath)
    except:
        return 0


def get_file_metadata(filepath, extension):
    """
    Extract detailed metadata from file based on type.
    Returns a dictionary with metadata information and content details.
    """
    metadata = {
        "size": get_file_size(filepath),
        "created": None,
        "modified": None,
        "details": "",
        "contents": []  # Store detailed content information
    }
    
    try:
        # Get modification time
        mtime = os.path.getmtime(filepath)
        metadata["modified"] = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass
    
    # Extract type-specific metadata and contents
    if extension == ".pcap" or extension == ".pcapng":
        metadata["details"] = "Network packet capture file"
        metadata["contents"].append("File type: Network packet capture (PCAP)")
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
                if header == b'\xa1\xb2\xc3\xd4':
                    metadata["details"] += " (standard format)"
                    metadata["contents"].append("Format: Standard PCAP (32-bit timestamps)")
                elif header == b'\xa1\xb2\xcd\x34':
                    metadata["details"] += " (nanosecond precision)"
                    metadata["contents"].append("Format: PCAP-NG (nanosecond precision)")
                else:
                    metadata["contents"].append("Format: Unknown or custom format")
                
                # Try to count packets by file size heuristic
                file_size = get_file_size(filepath)
                estimated_packets = max(1, file_size // 100)  # Rough estimate
                metadata["contents"].append(f"Estimated packets: ~{estimated_packets:,}")
        except:
            metadata["contents"].append("Format: Unable to determine")
    
    elif extension == ".zip":
        metadata["details"] = "ZIP archive file"
        metadata["contents"].append("File type: ZIP archive")
        try:
            import zipfile
            with zipfile.ZipFile(filepath, 'r') as z:
                file_list = z.namelist()
                file_count = len(file_list)
                metadata["details"] += f" (contains {file_count} items)"
                metadata["contents"].append(f"Items in archive: {file_count}")
                
                # List first 5 items
                for i, item in enumerate(file_list[:5]):
                    metadata["contents"].append(f"  • {item}")
                
                if file_count > 5:
                    metadata["contents"].append(f"  ... and {file_count - 5} more items")
                
                # Calculate total uncompressed size
                total_uncompressed = sum(z.getinfo(name).file_size for name in file_list)
                metadata["contents"].append(f"Total uncompressed size: {total_uncompressed:,} bytes")
        except Exception as e:
            metadata["details"] += " (corrupted or unreadable)"
            metadata["contents"].append("Status: Archive appears to be corrupted")
    
    elif extension in [".jpg", ".jpeg", ".png", ".gif", ".bmp"]:
        metadata["details"] = "Image file"
        metadata["contents"].append("File type: Image")
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
                if extension == ".png" and header[:4] == b'\x89PNG':
                    metadata["details"] += " (PNG format)"
                    metadata["contents"].append("Format: PNG (Portable Network Graphics)")
                    metadata["contents"].append("Compression: Lossless")
                elif extension in [".jpg", ".jpeg"] and header[:2] == b'\xff\xd8':
                    metadata["details"] += " (JPEG format)"
                    metadata["contents"].append("Format: JPEG (Joint Photographic Experts Group)")
                    metadata["contents"].append("Compression: Lossy")
                elif extension == ".gif":
                    metadata["contents"].append("Format: GIF (Graphics Interchange Format)")
                    metadata["contents"].append("Compression: Lossless")
                else:
                    metadata["contents"].append(f"Format: {extension.upper()}")
                
                # Add file size in human readable format
                size_mb = metadata["size"] / (1024 * 1024)
                metadata["contents"].append(f"Image size: {size_mb:.2f} MB")
        except:
            metadata["contents"].append("Format: Unable to determine")
    
    elif extension == ".pdf":
        metadata["details"] = "PDF document"
        metadata["contents"].append("File type: PDF (Portable Document Format)")
        try:
            with open(filepath, "rb") as f:
                content = f.read(1000)  # Read first 1000 bytes
                if b"Creator" in content or b"Producer" in content:
                    metadata["contents"].append("Status: Valid PDF structure detected")
                
                # Try to find title or metadata
                if b"/Title" in content:
                    metadata["contents"].append("Contains embedded metadata (Title field)")
                
                metadata["contents"].append(f"Document size: {metadata['size'] / 1024:.2f} KB")
        except:
            metadata["contents"].append("Status: Unable to read PDF metadata")
    
    elif extension == ".txt":
        metadata["details"] = "Text file"
        metadata["contents"].append("File type: Plain text")
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split('\n')
                metadata["contents"].append(f"Total lines: {len(lines)}")
                metadata["contents"].append(f"Total characters: {len(content)}")
                
                # Show first 3 lines of content
                metadata["contents"].append("Content preview:")
                for i, line in enumerate(lines[:3]):
                    if line.strip():
                        preview = line[:70] + "..." if len(line) > 70 else line
                        metadata["contents"].append(f"  Line {i+1}: {preview}")
                
                if len(lines) > 3:
                    metadata["contents"].append(f"  ... ({len(lines) - 3} more lines)")
        except:
            metadata["contents"].append("Status: Unable to read text content")
    
    elif extension in [".doc", ".docx"]:
        metadata["details"] = "Word document"
        metadata["contents"].append(f"File type: Microsoft Word document ({extension})")
        metadata["contents"].append(f"Document size: {metadata['size'] / 1024:.2f} KB")
    
    elif extension in [".rar", ".7z", ".tar", ".gz"]:
        metadata["details"] = "Archive file"
        metadata["contents"].append(f"File type: {extension.upper()} archive")
        metadata["contents"].append(f"Archive size: {metadata['size'] / (1024*1024):.2f} MB")
    
    return metadata


def create_category_folders(output_path):
    """Create output folders for each file category."""
    for category in FILE_CATEGORIES.keys():
        category_path = os.path.join(output_path, category)
        if not os.path.exists(category_path):
            os.makedirs(category_path)
            print(f"✓ Created folder: {category_path}")


def process_evidence_files():
    """
    Main function that scans evidence folder and sorts files.
    Returns a list of processed files for reporting.
    """
    # Check if evidence folder exists
    if not os.path.exists(EVIDENCE_FOLDER):
        print(f"Error: '{EVIDENCE_FOLDER}' folder not found!")
        return []
    
    # Create output folder structure
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
    
    create_category_folders(OUTPUT_FOLDER)
    
    # Track all processed files
    processed_files = []
    
    print("\n" + "="*70)
    print("SCANNING EVIDENCE FOLDER")
    print("="*70)
    
    # Walk through all files in evidence folder (including subfolders)
    for root, dirs, files in os.walk(EVIDENCE_FOLDER):
        for filename in files:
            filepath = os.path.join(root, filename)
            relative_path = os.path.relpath(filepath, EVIDENCE_FOLDER)
            
            # Get file extension and categorize
            extension = get_file_extension(filename)
            category = categorize_file(filename, extension)
            
            # Check if file is suspicious
            suspicious = is_file_suspicious(filename)
            
            # Get metadata
            metadata = get_file_metadata(filepath, extension)
            
            # Determine destination
            dest_folder = os.path.join(OUTPUT_FOLDER, category)
            dest_path = os.path.join(dest_folder, filename)
            
            # Copy file to categorized folder
            try:
                shutil.copy2(filepath, dest_path)
                status = "COPIED"
            except Exception as e:
                status = f"ERROR: {str(e)}"
            
            # Store file information
            file_info = {
                "original_path": filepath,
                "relative_path": relative_path,
                "filename": filename,
                "extension": extension,
                "category": category,
                "suspicious": suspicious,
                "metadata": metadata,
                "status": status
            }
            
            processed_files.append(file_info)
            
            # Print progress with detailed content information
            suspicious_flag = " [SUSPICIOUS]" if suspicious else ""
            print(f"\n• {filename}")
            print(f"  Type: {category} | Size: {metadata['size']:,} bytes{suspicious_flag}")
            
            # Print detailed contents
            if metadata['contents']:
                print(f"  Contents:")
                for content_line in metadata['contents']:
                    print(f"    {content_line}")
    
    return processed_files


def generate_report(processed_files):
    """
    Generate a summary report of all processed files.
    Saves report to a text file.
    """
    report_lines = []
    
    # Header
    report_lines.append("=" * 70)
    report_lines.append("DIGITAL FORENSICS EVIDENCE ANALYSIS REPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"Evidence Source: {EVIDENCE_FOLDER}")
    report_lines.append(f"Output Location: {OUTPUT_FOLDER}")
    report_lines.append("")
    
    # Summary statistics
    report_lines.append("SUMMARY")
    report_lines.append("-" * 70)
    report_lines.append(f"Total files processed: {len(processed_files)}")
    
    # Count by category
    category_counts = {}
    for file_info in processed_files:
        cat = file_info["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        description = FILE_CATEGORIES[category]["description"]
        report_lines.append(f"  • {category}: {count} file(s) - {description}")
    
    # Suspicious files
    suspicious_files = [f for f in processed_files if f["suspicious"]]
    report_lines.append("")
    report_lines.append(f"Suspicious files flagged: {len(suspicious_files)}")
    
    if suspicious_files:
        report_lines.append("")
        report_lines.append("SUSPICIOUS FILES DETECTED")
        report_lines.append("-" * 70)
        for file_info in suspicious_files:
            report_lines.append(f"• {file_info['filename']}")
            report_lines.append(f"  Category: {file_info['category']}")
            report_lines.append(f"  Size: {file_info['metadata']['size']} bytes")
            if file_info['metadata']['modified']:
                report_lines.append(f"  Modified: {file_info['metadata']['modified']}")
    
    # Detailed file listing
    report_lines.append("")
    report_lines.append("DETAILED FILE LISTING")
    report_lines.append("-" * 70)
    
    for file_info in processed_files:
        report_lines.append(f"\nFile: {file_info['filename']}")
        report_lines.append(f"  Original path: {file_info['relative_path']}")
        report_lines.append(f"  Category: {file_info['category']}")
        report_lines.append(f"  Extension: {file_info['extension']}")
        report_lines.append(f"  Size: {file_info['metadata']['size']:,} bytes")
        
        if file_info['metadata']['modified']:
            report_lines.append(f"  Modified: {file_info['metadata']['modified']}")
        
        if file_info['metadata']['details']:
            report_lines.append(f"  Type Details: {file_info['metadata']['details']}")
        
        # Add detailed contents
        if file_info['metadata']['contents']:
            report_lines.append(f"  Contents Information:")
            for content_line in file_info['metadata']['contents']:
                report_lines.append(f"    {content_line}")
        
        if file_info['suspicious']:
            report_lines.append(f"  WARNING: Suspicious file detected!")
        
        report_lines.append(f"  Status: {file_info['status']}")
    
    # Conclusion
    report_lines.append("")
    report_lines.append("=" * 70)
    report_lines.append("CONCLUSION")
    report_lines.append("-" * 70)
    report_lines.append(f"All {len(processed_files)} evidence file(s) have been processed and")
    report_lines.append(f"organized into categorized folders within '{OUTPUT_FOLDER}'.")
    
    if suspicious_files:
        report_lines.append(f"⚠ {len(suspicious_files)} suspicious file(s) have been flagged for review.")
    else:
        report_lines.append("No suspicious files were detected during analysis.")
    
    report_lines.append("")
    
    # Write report to file
    report_filename = os.path.join(OUTPUT_FOLDER, "EVIDENCE_REPORT.txt")
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    
    print("\n" + "="*70)
    print("REPORT GENERATED")
    print("="*70)
    print(f"✓ Report saved to: {report_filename}\n")
    
    # Also print to console
    print("\n".join(report_lines))


# ============================================================================
# MAIN PROGRAM
# ============================================================================

if __name__ == "__main__":
    print("\n")
    print("DIGITAL FORENSICS EVIDENCE SORTER")
    print("=" * 50)
    print("A beginner-friendly evidence analysis tool")
    print("")
    
    # Process evidence files
    processed_files = process_evidence_files()
    
    if processed_files:
        # Generate report
        generate_report(processed_files)
        print("\n✓ Program completed successfully!")
    else:
        print("\n✗ No files were processed. Check the 'evidence' folder.")
