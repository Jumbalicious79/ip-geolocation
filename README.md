# IP Geolocation Tool

Professional IP geolocation analysis tool using the IPinfo.io API. Provides detailed location, organization, and network information for IP addresses with enhanced security and bulk processing capabilities.

## 🌍 Features

- **Secure API token management** - Environment variables, config files, or interactive prompts
- **Bulk processing** - Process IP lists from files or interactive input
- **Input validation** - Validates IP address formats before processing
- **Rate limiting** - Respects API rate limits to avoid throttling
- **Multiple output formats** - CSV and JSON export options
- **Comprehensive error handling** - Graceful handling of network and API errors
- **Rich location data** - City, region, country, timezone, ISP, ASN information

## 📁 Project Structure

```
ip-geolocation/
├── README.md                    # This documentation
├── scripts/                     # Python geolocation tools
│   ├── main.py                 # Simple entry point
│   ├── geolocate_ips.py        # Enhanced geolocation engine
│   └── utils/                  # Shared utilities
├── docs/                        # API documentation & guides
├── data/                        # Historical geolocation results
├── input/                       # IP lists for processing
├── output/                      # Generated reports & exports
└── config/                      # Configuration files
    └── api_config.json.example # API token configuration template
```

## 🚀 Quick Start

### 1. Setup API Token (Choose One Method)

**Option A: Environment Variable (Recommended)**
```bash
export IPINFO_API_TOKEN="your_token_here"
```

**Option B: Config File**
```bash
cp config/api_config.json.example config/api_config.json
# Edit config/api_config.json with your token
```

**Option C: Interactive Prompt**
- The script will prompt for your token if not found

### 2. Get Your Free API Token
Visit [ipinfo.io/signup](https://ipinfo.io/signup) for a free account (1,000 requests/month).

### 3. Run the Tool

**Interactive Mode:**
```bash
cd scripts/
python3 main.py
# Follow prompts to enter IP addresses
```

**Single IP:**
```bash
cd scripts/
python3 geolocate_ips.py --ip 8.8.8.8
```

**Process from File:**
```bash
cd scripts/
python3 geolocate_ips.py --file ../input/ips.txt
```

**Advanced Options:**
```bash
cd scripts/
python3 geolocate_ips.py --file ../input/ips.txt --format both --output my_results
```

## 📝 Input Formats

### IP List Files
Create text files in `input/` directory with one IP per line:
```
8.8.8.8
1.1.1.1
152.89.249.236
# Comments start with #
```

### Sample Files Included
- `input/sample_ips.txt` - Example IP list

## 📊 Output Data

The tool provides comprehensive geolocation data:

| Field | Description | Example |
|-------|-------------|---------|
| IP | IP address | 8.8.8.8 |
| City | City name | Mountain View |
| Region | State/Province | California |
| Country | Country code | US |
| Country_Name | Full country name | United States |
| Org | Organization | AS15169 Google LLC |
| ISP | Internet Service Provider | Google LLC |
| ASN | Autonomous System Number | AS15169 |
| Location | Latitude,Longitude | 37.4056,-122.0775 |
| Timezone | Timezone | America/Los_Angeles |
| Postal | Postal/ZIP code | 94043 |

### Output Formats
- **CSV**: `output/ip_geolocation_YYYYMMDD_HHMMSS.csv`
- **JSON**: `output/ip_geolocation_YYYYMMDD_HHMMSS.json`

## 🔧 Command Line Options

```bash
python3 geolocate_ips.py [OPTIONS]

Options:
  --ip IP                 Single IP address to geolocate
  --file FILE            File containing IP addresses (one per line)
  --output FILENAME      Custom output filename
  --format {csv,json,both}  Output format (default: csv)
  --token TOKEN          IPinfo.io API token (overrides env var)
  --help                 Show help message
```

## 📈 Use Cases

- **Security Analysis**: Identify suspicious IP origins
- **Network Monitoring**: Track connection sources and patterns
- **Compliance**: Verify data residency requirements
- **Threat Intelligence**: Analyze attack vectors and botnet IPs
- **Business Intelligence**: Geographic analysis of traffic/customers
- **Research**: Study internet infrastructure and routing

## 🔒 Security Features

- **No hardcoded tokens** - Uses environment variables or config files
- **Input validation** - Prevents injection attacks through IP validation
- **Rate limiting** - Prevents API abuse and account suspension
- **Error handling** - Graceful failure without exposing sensitive data

## 📋 Historical Data

The `data/` directory contains previous geolocation results:
- `ip_geolocation_results.csv` - Results from original script
- Additional files as you process more IP lists

## 🛠️ Development

### Adding Features
- Extend `IPGeolocationTool` class in `scripts/geolocate_ips.py`
- Add new output formats or data sources
- Implement caching for performance optimization

### Dependencies
```bash
pip install requests  # HTTP requests for API calls
```

---

*Last Updated: 2025-07-31*  
*API: [IPinfo.io](https://ipinfo.io/developers)*