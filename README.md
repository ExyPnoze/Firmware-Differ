# FWDiffer

FWDiffer is a Python-based tool designed to compare two versions of firmware by analyzing the files within their directories. It helps identify files that have been **modified**, **added**, or **deleted** between two firmware versions.

## Features

- **Recursive File Scanning**: Scans the specified directories recursively to gather all file paths.
- **MD5 Hash Comparison**: Uses MD5 hashing to check for modifications in the content of files between two versions.
- **Report Generation**: Displays the list of modified, added, and deleted files.
- **Customization**: Option to display only specific categories of files (modified, added, or deleted).
