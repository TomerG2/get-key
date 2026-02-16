# get-key

A Python script for generating Google Vertex AI API authentication credentials. This tool handles service account authentication via JWT tokens and provides the necessary environment variables for accessing Vertex AI APIs.

## Features

- 🔐 **Service Account Authentication** - Uses Google Cloud service account JSON for secure authentication
- 🎯 **JWT Token Generation** - Creates and signs JWT tokens for OAuth2 flow
- ⚡ **Token Caching** - Caches access tokens to avoid unnecessary API calls
- 🛠️ **Command Line Interface** - Flexible path configuration via CLI arguments
- 📦 **Modern Dependency Management** - Uses `uv` for fast, reliable package management

## Requirements

- Python 3.8+
- [uv](https://docs.astral.sh/uv/) package manager
- Google Cloud service account with Vertex AI permissions
- Configuration files: `sa.json` and `config.json`

## Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd get-key
   ```

2. **Install dependencies:**
   ```bash
   make install
   ```
   *This uses `uv` to install `requests` and `cryptography` packages*

## Configuration

### Service Account File (`sa.json`)

You need a Google Cloud service account JSON file with the following structure:
```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "your-service-account@project.iam.gserviceaccount.com",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

### Configuration File (`config.json`)

Create a configuration file with your Vertex AI settings:
```json
{
  "projectId": "your-project-id",
  "location": "us-central1",
  "modelId": "your-model-id"
}
```

### File Placement

By default, the script looks for these files in the current directory:
- `./sa.json`
- `./config.json`

⚠️ **Security Note**: These files are automatically ignored by git (see `.gitignore`)

## Usage

### Quick Start

```bash
# Generate API credentials using default file locations
make key
```

### Command Line Options

```bash
# Use custom file paths
python getkey.py --sa /path/to/service-account.json --config /path/to/config.json

# Show help
python getkey.py --help
```

### Available Make Commands

```bash
make install    # Install dependencies using uv
make key        # Generate API credentials
make clean      # Clean Python cache files
make help       # Show available commands
```

## Output

The script outputs environment variables that you can use with your applications:

```bash
export LLM_URL=https://region-xyz-aiplatform.example.com/v1/projects/my-demo-project/locations/region-xyz/endpoints/openapi
export LLM_API_TOKEN=ya29.c.fake123xyz789abcdef_example_token_content...
```

You can copy and paste these export statements to set up your environment:

```bash
# Run the script and capture output
eval "$(python getkey.py)"

# Or manually copy the export statements
```

## Project Structure

```
get-key/
├── getkey.py           # Main authentication script
├── pyproject.toml      # Project dependencies and metadata
├── Makefile           # Build and run commands
├── .gitignore         # Git ignore rules (includes sa.json, config.json)
├── README.md          # This file
├── sa.json            # Service account credentials (you provide)
└── config.json        # Vertex AI configuration (you provide)
```

## How It Works

1. **Load Configuration** - Reads service account and Vertex AI config files
2. **Create JWT** - Generates a signed JWT using the service account private key
3. **Exchange for Token** - Exchanges JWT for an OAuth2 access token via Google's token endpoint
4. **Cache Token** - Stores token with expiration time for reuse
5. **Output Credentials** - Prints environment variables for external use

## Authentication Flow

```mermaid
graph TD
    A[Load sa.json] --> B[Create signed JWT]
    B --> C[POST to token endpoint]
    C --> D[Receive access token]
    D --> E[Cache with expiry]
    E --> F[Output environment variables]
```

## Troubleshooting

### Common Issues

**"Service account file not found"**
- Ensure `sa.json` exists in the current directory or specify custom path with `--sa`

**"Config file not found"**
- Ensure `config.json` exists in the current directory or specify custom path with `--config`

**"Invalid JSON"**
- Check that both JSON files are valid and properly formatted

**"Error signing JWT"**
- Verify that the private key in `sa.json` includes proper newline characters

### Debug Mode

Enable detailed logging by modifying the logging level in the script:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Security Considerations

- ⚠️ **Never commit** `sa.json` or `config.json` to version control
- 🔒 **Rotate service account keys** regularly
- 🛡️ **Use least-privilege** IAM roles for service accounts
- 🔐 **Store sensitive files** in secure locations outside the repository

## Dependencies

- **requests** (>=2.31.0) - HTTP library for API calls
- **cryptography** (>=41.0.0) - Cryptographic operations for JWT signing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request
