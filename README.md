# Digital Forensics Evidence Sorter

A beginner-friendly Python tool for automatically analyzing and organizing forensic evidence files.

## Overview

This project provides an automated solution for scanning, categorizing, and analyzing digital forensic evidence. It identifies file types, extracts metadata, flags suspicious files, and generates comprehensive reports.

## Features

✅ **Automatic File Categorization**
- Network captures (PCAP files)
- Images (PNG, JPG, GIF, BMP)
- Documents (PDF, TXT, DOC, DOCX)
- Archives (ZIP, RAR, 7Z, TAR, GZ)
- Unknown/suspicious files

✅ **Metadata Extraction**
- File size and modification dates
- Network packet format detection
- Archive contents analysis
- Image format validation

✅ **Suspicious File Detection**
- Flags files with keywords: confidential, secret, private, encrypted, attack, exploit
- Clear warning indicators in reports

✅ **Comprehensive Reporting**
- Summary statistics with file counts
- Detailed suspicious file listings
- Complete file inventory with metadata
- UTF-8 encoded output for special characters

## Requirements

- Python 3.6+
- No external dependencies required (uses Python standard library only)

## Usage

### Quick Start

1. Place your forensic evidence files in the `evidence/` folder

2. Run the script:
```bash
python evidence_sorter.py
```

3. View the results:
   - Organized files in `evidence_sorted/` directory
   - Summary report in `evidence_sorted/EVIDENCE_REPORT.txt`

### Folder Structure

```
project/
├── evidence/                    # Input folder with evidence files
│   ├── file1.pcap
│   ├── file2.txt
│   └── ...
├── evidence_sorter.py          # Main script
└── evidence_sorted/            # Output folder (created by script)
    ├── documents/              # Categorized files
    ├── images/
    ├── network_captures/
    ├── archives/
    ├── unknown/
    └── EVIDENCE_REPORT.txt     # Analysis report
```

## Script Output

### Console Output
The script displays:
- Progress of file scanning
- File categorization and sizes
- Suspicious file flags

### Report File (EVIDENCE_REPORT.txt)
Contains:
- Timestamp and analysis parameters
- Summary statistics by category
- List of flagged suspicious files
- Detailed file inventory with metadata
- Analysis conclusion

## Example Output

```
DIGITAL FORENSICS EVIDENCE ANALYSIS REPORT
Generated: 2026-01-28 12:08:37
Evidence Source: evidence
Output Location: evidence_sorted

SUMMARY
Total files processed: 8
  • archives: 1 file(s) - Archive/compressed files
  • documents: 3 file(s) - Document files (text, PDF)
  • images: 3 file(s) - Image files (pictures, screenshots)
  • network_captures: 1 file(s) - Network capture files (packet analysis)

Suspicious files flagged: 2
```

## Code Structure

The script is organized with clear sections:

- **Configuration**: Editable file categories and suspicious patterns
- **Helper Functions**: File processing utilities
- **Main Processing**: Core scanning and categorization logic
- **Report Generation**: Results formatting and output

All functions include explanatory comments for beginner-level understanding.

## Customization

### Add New File Types

Edit the `FILE_CATEGORIES` dictionary in the script:

```python
FILE_CATEGORIES = {
    "your_category": {
        "extensions": [".ext1", ".ext2"],
        "description": "Category description"
    },
    # ... existing categories
}
```

### Add Suspicious Patterns

Modify the `SUSPICIOUS_PATTERNS` list:

```python
SUSPICIOUS_PATTERNS = [
    "pattern1",
    "pattern2",
    # ... existing patterns
]
```

### Change Evidence Folder

Modify these variables at the top of the script:

```python
EVIDENCE_FOLDER = "your_folder_name"
OUTPUT_FOLDER = "your_output_folder_name"
```

## Design Philosophy

- **Beginner-Friendly**: Clear variable names, extensive comments, simple logic
- **No Complex Libraries**: Uses only Python standard library
- **No OOP**: Functional programming approach for easier understanding
- **Readable Output**: Formatted reports with proper encoding

## Metadata Capabilities

### PCAP Files
- Detects standard vs nanosecond precision formats
- Identifies packet capture format variations

### ZIP Archives
- Counts contained items
- Identifies corrupted archives

### Image Files
- Validates PNG format
- Identifies JPEG format
- Detects format mismatches

### Text Files
- Extracts size and modification date
- Flags suspicious content by filename

## Testing

The tool has been tested with:
- Multiple image formats (PNG, JPG)
- PDF documents
- Text files
- Network packet captures (PCAP)
- ZIP archives
- Suspicious filename patterns

## Performance

- Efficiently processes multiple files
- Recursive folder scanning
- Safe file copying (preserves metadata)
- Fast metadata extraction

## Limitations

- Text content analysis not performed (filename-based detection only)
- Archive scanning limited to file count (no recursive analysis)
- Limited to common file formats
- Windows/Linux compatible path handling

## Future Enhancements

Potential improvements:
- Hash-based duplicate detection
- Timeline analysis of file modification dates
- Deeper archive inspection
- Content-based file type detection
- GUI interface
- Database logging

## License

This project is created for educational and forensic analysis purposes.

## Author

Created as part of Final Year Project (FYP) - Digital Forensics Tool

---

**Note**: This tool is designed for legitimate forensic analysis. Users are responsible for proper evidence handling and chain of custody procedures.
