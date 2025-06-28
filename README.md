# heybabe

TLS ClientHello testing tool

## Installation

### From Binary Releases
Download the latest release for your platform from the [GitHub releases page](https://github.com/markpash/heybabe/releases).

### From Docker
```bash
# Pull the latest version
docker pull ghcr.io/markpash/heybabe:latest

# Or pull a specific version
docker pull ghcr.io/markpash/heybabe:v1.0.0
```

### From Source
```bash
git clone https://github.com/markpash/heybabe.git
cd heybabe
go build -o heybabe .
```

## Usage

### Basic Usage
```sh
$ heybabe --sni twitter.com
```

### Using Docker
```sh
# Basic usage with Docker
$ docker run ghcr.io/markpash/heybabe:latest --sni twitter.com

# With custom port
$ docker run ghcr.io/markpash/heybabe:latest --sni twitter.com --port 8443

# With manual IP address
$ docker run ghcr.io/markpash/heybabe:latest --sni twitter.com --ip 1.2.3.4

# With repeat option
$ docker run ghcr.io/markpash/heybabe:latest --sni twitter.com --repeat 2

# For better QUIC performance (requires --privileged or specific capabilities)
$ docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN ghcr.io/markpash/heybabe:latest --sni twitter.com
```

### Docker Networking Considerations

The application performs various TLS tests including QUIC connections. For optimal performance:

- **QUIC Buffer Size**: You may see warnings about UDP buffer size. This is normal in containers and doesn't affect functionality.
- **Network Capabilities**: For best QUIC performance, run with `--cap-add=NET_ADMIN` or `--privileged` (use with caution).
- **Container Networking**: The app makes outbound connections only, so no special port mapping is required.

### Advanced Examples

To manually provide an IP address and avoid DNS lookup:
```sh
$ heybabe --sni twitter.com --ip 1.2.3.4
```

To specify a non-default port:
```sh
$ heybabe --sni twitter.com --port 8443
```

To repeat a test multiple times:
```sh
$ heybabe --sni twitter.com --repeat 2
```

To use only IPv4 or IPv6:
```sh
$ heybabe --sni twitter.com -4  # IPv4 only
$ heybabe --sni twitter.com -6  # IPv6 only
```

To change log level and format:
```sh
$ heybabe --sni twitter.com --loglevel INFO
$ heybabe --sni twitter.com --json  # JSON log format
```

## Command Line Options

```
NAME
  heybabe

FLAGS
  -4                      only resolve IPv4 (only works when IP is not set)
  -6                      only resolve IPv6 (only works when IP is not set)
      --sni STRING        tls sni (if IP flag not provided, this SNI will be resolved by system DNS)
      --port UINT         tls port (default: 443)
      --ip STRING         manually provide IP (no DNS lookup)
      --repeat UINT       number of times to repeat each test (default: 1)
      --loglevel STRING   specify a log level (valid values: [DEBUG INFO WARN ERROR]) (default: DEBUG)
  -j, --json              log in json format
      --version           displays version number
```

## Docker Images

Docker images are automatically built and published to GitHub Container Registry (GHCR) for each release. Images are available for multiple architectures:

- `linux/amd64`
- `linux/arm64` 
- `linux/arm/v7`

### Available Tags

- `latest` - Latest release
- `v1.0.0` - Specific version
- `v1.0` - Major.minor version
- `main-abc123` - Branch with commit SHA

### Pulling Images

```bash
# Latest version
docker pull ghcr.io/markpash/heybabe:latest

# Specific version
docker pull ghcr.io/markpash/heybabe:v1.0.0

# Specific architecture (if needed)
docker pull --platform linux/arm64 ghcr.io/markpash/heybabe:latest
```

## Development

### Building from Source
```bash
git clone https://github.com/markpash/heybabe.git
cd heybabe
go build -o heybabe .
```

### Running Tests
```bash
go test ./...
```

### Building Docker Image Locally
```bash
docker build -t heybabe .
docker run heybabe --sni example.com
```
