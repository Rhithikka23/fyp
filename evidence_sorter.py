"""
Digital Forensics Evidence Sorter - Enhanced Edition
This program scans an evidence folder, categorizes files by type,
extracts detailed visual content information, and generates comprehensive analysis reports.
"""

import os
import shutil
import struct
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

EVIDENCE_FOLDER = "evidence"
OUTPUT_FOLDER = "evidence_sorted"

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

SUSPICIOUS_PATTERNS = [
    "confidential",
    "secret",
    "private",
    "encrypted",
    "attack",
    "exploit",
]

# ============================================================================
# HELPER FUNCTIONS - IMAGE ANALYSIS
# ============================================================================

def get_image_dimensions(filepath):
    """Extract image dimensions from file header."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(24)
            
            # PNG format
            if header[:4] == b'\x89PNG':
                width = struct.unpack('>I', header[16:20])[0]
                height = struct.unpack('>I', header[20:24])[0]
                return width, height
            
            # JPEG format
            elif header[:2] == b'\xff\xd8':
                with open(filepath, "rb") as img:
                    img.seek(0)
                    data = img.read()
                    for marker in [b'\xff\xc0', b'\xff\xc1', b'\xff\xc2']:
                        idx = data.find(marker)
                        if idx > 0:
                            height = struct.unpack('>H', data[idx+5:idx+7])[0]
                            width = struct.unpack('>H', data[idx+7:idx+9])[0]
                            return width, height
            
            # GIF format
            elif header[:3] == b'GIF':
                width = struct.unpack('<H', header[6:8])[0]
                height = struct.unpack('<H', header[8:10])[0]
                return width, height
            
            # BMP format
            elif header[:2] == b'BM':
                width = struct.unpack('<I', header[18:22])[0]
                height = struct.unpack('<I', header[22:26])[0]
                return width, height
    except:
        pass
    
    return None, None


# ============================================================================
# HELPER FUNCTIONS - PDF ANALYSIS
# ============================================================================

def extract_pdf_info(filepath):
    """Extract detailed information from PDF file."""
    info = {}
    try:
        with open(filepath, "rb") as f:
            content = f.read()
            
            # PDF version
            if b'%PDF-' in content:
                version_idx = content.find(b'%PDF-')
                version = content[version_idx:version_idx+10].decode('utf-8', errors='ignore')
                info['version'] = version.strip()
            
            # Count pages
            page_count = content.count(b'/Type /Page') + content.count(b'/Type/Page')
            info['estimated_pages'] = max(1, page_count)
            
            # Extract metadata
            for key in ['/Title', '/Author', '/Creator', '/Subject', '/Producer']:
                if key.encode() in content:
                    idx = content.find(key.encode())
                    snippet = content[idx:idx+150]
                    if b'(' in snippet:
                        start = snippet.find(b'(')
                        end = snippet.find(b')', start)
                        if end > start:
                            value = snippet[start+1:end].decode('utf-8', errors='ignore')
                            clean_key = key.replace('/', '').lower()
                            if value.strip():
                                info[clean_key] = value
            
            # Check for suspicious features
            suspicious = []
            if b'/JavaScript' in content:
                suspicious.append("JavaScript code")
            if b'/OpenAction' in content:
                suspicious.append("Auto-execute action")
            if b'/EmbeddedFile' in content:
                suspicious.append("Embedded files")
            if b'/Flash' in content:
                suspicious.append("Flash content")
            if b'/Launch' in content:
                suspicious.append("Launch action")
            
            if suspicious:
                info['suspicious_features'] = suspicious
    except:
        pass
    
    return info


# ============================================================================
# HELPER FUNCTIONS - PCAP ANALYSIS
# ============================================================================

def analyze_pcap_file(filepath):
    """Analyze PCAP file and extract detailed packet information."""
    info = {}
    try:
        with open(filepath, "rb") as f:
            global_header = f.read(24)
            
            if len(global_header) >= 4:
                magic = struct.unpack('<I', global_header[:4])[0]
                
                # Determine format and byte order
                if magic == 0xa1b2c3d4:
                    info['format'] = 'Standard PCAP (32-bit timestamps)'
                    is_nano = False
                elif magic == 0xa1b2cd34:
                    info['format'] = 'PCAP-NG (nanosecond precision)'
                    is_nano = True
                elif magic == 0xd4c3b2a1:
                    info['format'] = 'Standard PCAP (swapped byte order)'
                    is_nano = False
                else:
                    info['format'] = 'Unknown PCAP variant'
                    return info
                
                # Extract version
                if len(global_header) >= 8 and not is_nano:
                    version_major = struct.unpack('<H', global_header[4:6])[0]
                    version_minor = struct.unpack('<H', global_header[6:8])[0]
                    info['version'] = f"{version_major}.{version_minor}"
                
                # Extract snaplen
                if len(global_header) >= 16:
                    snaplen = struct.unpack('<I', global_header[16:20])[0]
                    info['max_packet_size'] = f"{snaplen:,} bytes"
                
                # Count packets with detailed analysis
                packet_count = 0
                protocols = {}
                timestamps = []
                
                f.seek(24)
                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    try:
                        ts_sec = struct.unpack('<I', packet_header[0:4])[0]
                        ts_usec = struct.unpack('<I', packet_header[4:8])[0]
                        pkt_len = struct.unpack('<I', packet_header[8:12])[0]
                        
                        if pkt_len > 65535:
                            break
                        
                        timestamps.append(ts_sec)
                        packet_count += 1
                        
                        # Read packet data for protocol analysis
                        pkt_data = f.read(pkt_len)
                        
                        # Simple protocol detection (Ethernet frame)
                        if len(pkt_data) >= 14:
                            eth_type = struct.unpack('>H', pkt_data[12:14])[0]
                            
                            if eth_type == 0x0800:
                                protocol = 'IPv4'
                            elif eth_type == 0x0806:
                                protocol = 'ARP'
                            elif eth_type == 0x86DD:
                                protocol = 'IPv6'
                            else:
                                protocol = f'Other ({hex(eth_type)})'
                            
                            protocols[protocol] = protocols.get(protocol, 0) + 1
                    except:
                        break
                
                info['total_packets'] = packet_count
                
                if packet_count > 0:
                    info['packet_size_avg'] = f"{os.path.getsize(filepath) // packet_count:.0f} bytes"
                
                if protocols:
                    info['protocols'] = protocols
                
                if timestamps:
                    try:
                        start_time = datetime.fromtimestamp(min(timestamps))
                        end_time = datetime.fromtimestamp(max(timestamps))
                        info['capture_start'] = start_time.strftime("%Y-%m-%d %H:%M:%S")
                        info['capture_end'] = end_time.strftime("%Y-%m-%d %H:%M:%S")
                        duration = max(timestamps) - min(timestamps)
                        info['capture_duration'] = f"{duration} seconds"
                    except:
                        pass
    
    except Exception as e:
        info['error'] = str(e)
    
    return info


# ============================================================================
# HELPER FUNCTIONS - BASIC UTILITIES
# ============================================================================

def get_file_extension(filename):
    """Extract file extension in lowercase."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def categorize_file(filename, extension):
    """Determine which category a file belongs to."""
    for category, details in FILE_CATEGORIES.items():
        if extension in details["extensions"]:
            return category
    return "unknown"


def is_file_suspicious(filename):
    """Check if filename contains suspicious keywords."""
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


# ============================================================================
# COMPREHENSIVE FILE ANALYSIS
# ============================================================================

def get_file_metadata(filepath, extension):
    """
    Extract comprehensive metadata and visual content information from file.
    """
    metadata = {
        "size": get_file_size(filepath),
        "modified": None,
        "details": "",
        "contents": []
    }
    
    try:
        mtime = os.path.getmtime(filepath)
        metadata["modified"] = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass
    
    # ==================== IMAGE FILES ====================
    if extension in [".jpg", ".jpeg", ".png", ".gif", ".bmp"]:
        metadata["details"] = "Image file"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("IMAGE ANALYSIS")
        metadata["contents"].append("=" * 60)
        
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
                
                if extension == ".png" and header[:4] == b'\x89PNG':
                    metadata["contents"].append("Format: PNG (Portable Network Graphics)")
                    metadata["contents"].append("Compression: Lossless")
                elif extension in [".jpg", ".jpeg"] and header[:2] == b'\xff\xd8':
                    metadata["contents"].append("Format: JPEG (Joint Photographic Experts Group)")
                    metadata["contents"].append("Compression: Lossy")
                elif extension == ".gif":
                    metadata["contents"].append("Format: GIF (Graphics Interchange Format)")
                    metadata["contents"].append("Compression: Lossless with palette")
                elif extension == ".bmp":
                    metadata["contents"].append("Format: BMP (Bitmap)")
                    metadata["contents"].append("Compression: Uncompressed or RLE")
                
                # Get dimensions
                width, height = get_image_dimensions(filepath)
                if width and height:
                    metadata["contents"].append(f"Dimensions: {width:,} x {height:,} pixels")
                    megapixels = (width * height) / 1000000
                    metadata["contents"].append(f"Megapixels: {megapixels:.2f} MP")
                
                size_mb = metadata["size"] / (1024 * 1024)
                size_kb = metadata["size"] / 1024
                if size_mb > 1:
                    metadata["contents"].append(f"File Size: {size_mb:.2f} MB")
                else:
                    metadata["contents"].append(f"File Size: {size_kb:.2f} KB")
                
                if width and height:
                    aspect_ratio = width / height
                    metadata["contents"].append(f"Aspect Ratio: {aspect_ratio:.2f}:1")
                
        except Exception as e:
            metadata["contents"].append(f"Analysis error: {str(e)}")
    
    # ==================== PDF FILES ====================
    elif extension == ".pdf":
        metadata["details"] = "PDF document"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("PDF DOCUMENT ANALYSIS")
        metadata["contents"].append("=" * 60)
        
        size_kb = metadata['size'] / 1024
        metadata["contents"].append(f"File Size: {size_kb:.2f} KB")
        
        pdf_info = extract_pdf_info(filepath)
        
        if 'version' in pdf_info:
            metadata["contents"].append(f"PDF Version: {pdf_info['version']}")
        
        if 'estimated_pages' in pdf_info:
            metadata["contents"].append(f"Estimated Pages: {pdf_info['estimated_pages']}")
        
        metadata["contents"].append("-" * 60)
        metadata["contents"].append("DOCUMENT METADATA:")
        
        if 'title' in pdf_info:
            metadata["contents"].append(f"  Title: {pdf_info['title']}")
        if 'author' in pdf_info:
            metadata["contents"].append(f"  Author: {pdf_info['author']}")
        if 'creator' in pdf_info:
            metadata["contents"].append(f"  Creator: {pdf_info['creator']}")
        if 'subject' in pdf_info:
            metadata["contents"].append(f"  Subject: {pdf_info['subject']}")
        if 'producer' in pdf_info:
            metadata["contents"].append(f"  Producer: {pdf_info['producer']}")
        
        if 'suspicious_features' in pdf_info:
            metadata["contents"].append("-" * 60)
            metadata["contents"].append("SUSPICIOUS FEATURES DETECTED:")
            for feature in pdf_info['suspicious_features']:
                metadata["contents"].append(f"  [!] {feature}")
    
    # ==================== ZIP FILES ====================
    elif extension == ".zip":
        metadata["details"] = "ZIP archive"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("ZIP ARCHIVE CONTENTS ANALYSIS")
        metadata["contents"].append("=" * 60)
        
        try:
            import zipfile
            with zipfile.ZipFile(filepath, 'r') as z:
                file_list = z.namelist()
                file_count = len(file_list)
                
                metadata["contents"].append(f"Total Items: {file_count}")
                metadata["contents"].append("")
                metadata["contents"].append("DETAILED FILE LISTING:")
                metadata["contents"].append("-" * 60)
                
                total_uncompressed = 0
                total_compressed = 0
                max_name_len = max(len(name) for name in file_list) if file_list else 20
                
                for item in sorted(file_list):
                    info = z.getinfo(item)
                    uncompressed_size = info.file_size
                    compressed_size = info.compress_size
                    
                    total_uncompressed += uncompressed_size
                    total_compressed += compressed_size
                    
                    # Format output
                    is_dir = item.endswith('/')
                    symbol = "[DIR]" if is_dir else "[FILE]"
                    
                    # Human-readable size
                    if uncompressed_size > 1024*1024:
                        size_str = f"{uncompressed_size / (1024*1024):.2f} MB"
                    elif uncompressed_size > 1024:
                        size_str = f"{uncompressed_size / 1024:.2f} KB"
                    else:
                        size_str = f"{uncompressed_size} B"
                    
                    metadata["contents"].append(f"{symbol:6} {item:40} {size_str:>12}")
                
                metadata["contents"].append("-" * 60)
                metadata["contents"].append("ARCHIVE STATISTICS:")
                metadata["contents"].append(f"  Total Uncompressed: {total_uncompressed:,} bytes ({total_uncompressed/(1024*1024):.2f} MB)")
                metadata["contents"].append(f"  Total Compressed: {total_compressed:,} bytes ({total_compressed/(1024*1024):.2f} MB)")
                
                if total_uncompressed > 0:
                    ratio = 100 - (total_compressed / total_uncompressed * 100)
                    metadata["contents"].append(f"  Compression Ratio: {ratio:.1f}%")
                
                # Check for suspicious files
                suspicious_in_zip = [f for f in file_list if any(p in f.lower() for p in SUSPICIOUS_PATTERNS)]
                if suspicious_in_zip:
                    metadata["contents"].append("")
                    metadata["contents"].append("SUSPICIOUS FILES IN ARCHIVE:")
                    for suspicious_file in suspicious_in_zip:
                        metadata["contents"].append(f"  [!] {suspicious_file}")
        
        except Exception as e:
            metadata["details"] += " (corrupted or unreadable)"
            metadata["contents"].append(f"Error reading archive: {str(e)}")
    
    # ==================== NETWORK CAPTURE FILES ====================
    elif extension in [".pcap", ".pcapng"]:
        metadata["details"] = "Network packet capture"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("PCAP FILE ANALYSIS")
        metadata["contents"].append("=" * 60)
        
        pcap_info = analyze_pcap_file(filepath)
        
        if 'format' in pcap_info:
            metadata["contents"].append(f"Format: {pcap_info['format']}")
        
        if 'version' in pcap_info:
            metadata["contents"].append(f"Version: {pcap_info['version']}")
        
        if 'max_packet_size' in pcap_info:
            metadata["contents"].append(f"Max Packet Size: {pcap_info['max_packet_size']}")
        
        metadata["contents"].append("")
        metadata["contents"].append("PACKET STATISTICS:")
        
        if 'total_packets' in pcap_info:
            metadata["contents"].append(f"  Total Packets: {pcap_info['total_packets']:,}")
        
        if 'packet_size_avg' in pcap_info:
            metadata["contents"].append(f"  Average Packet Size: {pcap_info['packet_size_avg']}")
        
        size_mb = metadata['size'] / (1024*1024)
        metadata["contents"].append(f"  File Size: {size_mb:.2f} MB")
        
        if 'capture_start' in pcap_info:
            metadata["contents"].append("")
            metadata["contents"].append("CAPTURE TIMEFRAME:")
            metadata["contents"].append(f"  Start: {pcap_info['capture_start']}")
            metadata["contents"].append(f"  End: {pcap_info['capture_end']}")
            metadata["contents"].append(f"  Duration: {pcap_info['capture_duration']}")
        
        if 'protocols' in pcap_info:
            metadata["contents"].append("")
            metadata["contents"].append("PROTOCOL DISTRIBUTION:")
            for protocol, count in sorted(pcap_info['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / pcap_info.get('total_packets', 1)) * 100
                metadata["contents"].append(f"  {protocol}: {count:,} packets ({percentage:.1f}%)")
    
    # ==================== TEXT FILES ====================
    elif extension == ".txt":
        metadata["details"] = "Text file"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("TEXT FILE CONTENTS")
        metadata["contents"].append("=" * 60)
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split('\n')
                
                metadata["contents"].append(f"Total Lines: {len(lines):,}")
                metadata["contents"].append(f"Total Characters: {len(content):,}")
                metadata["contents"].append(f"File Size: {metadata['size']:,} bytes")
                metadata["contents"].append("")
                metadata["contents"].append("CONTENT PREVIEW:")
                metadata["contents"].append("-" * 60)
                
                # Show content with line numbers
                for i, line in enumerate(lines[:30]):
                    if i < len(lines):
                        metadata["contents"].append(f"{i+1:4}: {line}")
                
                if len(lines) > 30:
                    metadata["contents"].append(f"... and {len(lines) - 30} more lines")
        
        except Exception as e:
            metadata["contents"].append(f"Error reading file: {str(e)}")
    
    # ==================== WORD DOCUMENTS ====================
    elif extension in [".doc", ".docx"]:
        metadata["details"] = "Word document"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("WORD DOCUMENT INFO")
        metadata["contents"].append("=" * 60)
        metadata["contents"].append(f"File Type: Microsoft Word ({extension.upper()})")
        metadata["contents"].append(f"File Size: {metadata['size'] / 1024:.2f} KB")
        
        if extension == ".docx":
            try:
                import zipfile
                with zipfile.ZipFile(filepath, 'r') as z:
                    metadata["contents"].append("")
                    metadata["contents"].append("DOCUMENT STRUCTURE:")
                    
                    if 'docProps/core.xml' in z.namelist():
                        metadata["contents"].append("  Contains: Document properties metadata")
                    if 'word/document.xml' in z.namelist():
                        metadata["contents"].append("  Contains: Main document content")
                    if 'word/styles.xml' in z.namelist():
                        metadata["contents"].append("  Contains: Stylesheet definitions")
                    if 'word/theme/theme1.xml' in z.namelist():
                        metadata["contents"].append("  Contains: Theme and formatting")
                    
                    # Count images
                    media_files = [f for f in z.namelist() if 'media/' in f]
                    if media_files:
                        metadata["contents"].append(f"  Contains: {len(media_files)} embedded images/media")
                    
                    # Count relations
                    rels = [f for f in z.namelist() if '.rels' in f]
                    metadata["contents"].append(f"  Document Relations: {len(rels)} relationship files")
            except:
                pass
    
    # ==================== OTHER ARCHIVES ====================
    elif extension in [".rar", ".7z", ".tar", ".gz"]:
        metadata["details"] = f"{extension.upper()} archive"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append(f"{extension.upper()} ARCHIVE")
        metadata["contents"].append("=" * 60)
        metadata["contents"].append(f"Archive Type: {extension.upper()}")
        metadata["contents"].append(f"Archive Size: {metadata['size'] / (1024*1024):.2f} MB")
        metadata["contents"].append("")
        metadata["contents"].append("Note: Detailed extraction requires external tools")
        metadata["contents"].append("Consider using: 7z, WinRAR, or tar command-line tools")
    
    # ==================== UNKNOWN FILES ====================
    else:
        metadata["details"] = "Unknown file type"
        metadata["contents"].append("=" * 60)
        metadata["contents"].append("UNKNOWN FILE TYPE")
        metadata["contents"].append("=" * 60)
        metadata["contents"].append(f"File Extension: {extension}")
        metadata["contents"].append(f"File Size: {metadata['size']:,} bytes")
        metadata["contents"].append("Unable to analyze: File type not recognized")
    
    return metadata


def create_category_folders(output_path):
    """Create output folders for each file category."""
    for category in FILE_CATEGORIES.keys():
        category_path = os.path.join(output_path, category)
        if not os.path.exists(category_path):
            os.makedirs(category_path)
            print(f"✓ Created folder: {category_path}")


def process_evidence_files():
    """Main function that scans evidence folder and sorts files."""
    if not os.path.exists(EVIDENCE_FOLDER):
        print(f"Error: '{EVIDENCE_FOLDER}' folder not found!")
        return []
    
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
    
    create_category_folders(OUTPUT_FOLDER)
    
    processed_files = []
    
    print("\n" + "="*70)
    print("SCANNING EVIDENCE FOLDER")
    print("="*70)
    
    for root, dirs, files in os.walk(EVIDENCE_FOLDER):
        for filename in files:
            filepath = os.path.join(root, filename)
            relative_path = os.path.relpath(filepath, EVIDENCE_FOLDER)
            
            extension = get_file_extension(filename)
            category = categorize_file(filename, extension)
            suspicious = is_file_suspicious(filename)
            metadata = get_file_metadata(filepath, extension)
            
            dest_folder = os.path.join(OUTPUT_FOLDER, category)
            dest_path = os.path.join(dest_folder, filename)
            
            try:
                shutil.copy2(filepath, dest_path)
                status = "COPIED"
            except Exception as e:
                status = f"ERROR: {str(e)}"
            
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
            
            # Console output
            suspicious_flag = " [SUSPICIOUS]" if suspicious else ""
            print(f"\n• {filename}")
            print(f"  Type: {category} | Size: {metadata['size']:,} bytes{suspicious_flag}")
            
            # Print detailed contents
            if metadata['contents']:
                for content_line in metadata['contents']:
                    print(f"  {content_line}")
    
    return processed_files


def generate_report(processed_files):
    """Generate comprehensive analysis report."""
    report_lines = []
    
    # Header
    report_lines.append("=" * 70)
    report_lines.append("DIGITAL FORENSICS EVIDENCE ANALYSIS REPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"Evidence Source: {EVIDENCE_FOLDER}")
    report_lines.append(f"Output Location: {OUTPUT_FOLDER}")
    report_lines.append("")
    
    # Summary
    report_lines.append("SUMMARY")
    report_lines.append("-" * 70)
    report_lines.append(f"Total files processed: {len(processed_files)}")
    
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
            report_lines.append(f"  Size: {file_info['metadata']['size']:,} bytes")
            if file_info['metadata']['modified']:
                report_lines.append(f"  Modified: {file_info['metadata']['modified']}")
    
    # Detailed file listing
    report_lines.append("")
    report_lines.append("DETAILED FILE ANALYSIS")
    report_lines.append("=" * 70)
    
    for file_info in processed_files:
        report_lines.append(f"\n{'='*70}")
        report_lines.append(f"FILE: {file_info['filename']}")
        report_lines.append(f"{'='*70}")
        report_lines.append(f"Original path: {file_info['relative_path']}")
        report_lines.append(f"Category: {file_info['category']}")
        report_lines.append(f"Extension: {file_info['extension']}")
        report_lines.append(f"Size: {file_info['metadata']['size']:,} bytes")
        
        if file_info['metadata']['modified']:
            report_lines.append(f"Modified: {file_info['metadata']['modified']}")
        
        if file_info['metadata']['details']:
            report_lines.append(f"Type: {file_info['metadata']['details']}")
        
        # Add detailed contents
        if file_info['metadata']['contents']:
            report_lines.append("")
            for content_line in file_info['metadata']['contents']:
                report_lines.append(content_line)
        
        if file_info['suspicious']:
            report_lines.append("")
            report_lines.append("WARNING: Suspicious file detected!")
        
        report_lines.append(f"\nStatus: {file_info['status']}")
    
    # Conclusion
    report_lines.append("")
    report_lines.append("=" * 70)
    report_lines.append("ANALYSIS CONCLUSION")
    report_lines.append("=" * 70)
    report_lines.append(f"All {len(processed_files)} evidence file(s) have been processed and")
    report_lines.append(f"organized into categorized folders within '{OUTPUT_FOLDER}'.")
    
    if suspicious_files:
        report_lines.append(f"\nWARNING: {len(suspicious_files)} suspicious file(s) detected!")
        report_lines.append("These files should be reviewed carefully.")
    else:
        report_lines.append("\nNo suspicious files were detected during analysis.")
    
    report_lines.append("")
    
    # Write report
    report_filename = os.path.join(OUTPUT_FOLDER, "EVIDENCE_REPORT.txt")
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    
    print("\n" + "="*70)
    print("REPORT GENERATED")
    print("="*70)
    print(f"✓ Report saved to: {report_filename}\n")
    
    # Print to console
    print("\n".join(report_lines))


# ============================================================================
# MAIN PROGRAM
# ============================================================================

if __name__ == "__main__":
    print("\n")
    print("DIGITAL FORENSICS EVIDENCE SORTER - ENHANCED EDITION")
    print("=" * 70)
    print("Comprehensive file analysis and forensic evidence categorization")
    print("")
    
    processed_files = process_evidence_files()
    
    if processed_files:
        generate_report(processed_files)
        print("\n✓ Program completed successfully!")
    else:
        print("\n✗ No files were processed. Check the 'evidence' folder.")
