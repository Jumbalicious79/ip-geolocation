# Input Directory

This directory contains IP address and domain name lists for geolocation processing.

## File Format

**Text files with one entry per line (IPs and domains are auto-detected):**
```
8.8.8.8
1.1.1.1
cloudflare.com
bbc.co.uk
# Lines starting with # are comments and will be ignored
```

## Example Files

- `sample_ips.txt` - Sample IPs and domains for testing

## Processing

```bash
cd ../scripts/
python3 geolocate_ips.py --file ../input/sample_ips.txt
```

Results are automatically saved to `../output/` directory.
