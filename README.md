# encript_tool

A secure encryption tool using AES-256-GCM with Argon2 key derivation, featuring both CLI and GUI interfaces.

## Features

- **Strong Encryption**: AES-256-GCM authenticated encryption
- **Secure Key Derivation**: Argon2 password hashing with configurable parameters
- **Multiple Interfaces**: Command-line and graphical user interface
- **Flexible Input**: Encrypt/decrypt strings or files
- **Streaming Support**: Handle large files efficiently with streaming mode
- **Configuration Management**: Customizable settings via TOML config file
- **Password Options**: Direct input, environment variables, or interactive prompt

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/WatanabeYuito21/encript_tool.git
cd encript_tool

# Build CLI version
cargo build --release

# Build with GUI support
cargo build --release --features gui
```

The compiled binary will be available at `target/release/encript_tool`.

## Usage

### CLI Mode

#### Encrypt a String

```bash
# From argument
encript_tool encrypt "Hello, World!" -p mypassword

# From stdin
echo "Secret message" | encript_tool encrypt -p mypassword

# Using environment variable for password
export CRYPT_PASSWORD="mypassword"
encript_tool encrypt "Hello, World!" --password-env CRYPT_PASSWORD

# Verbose output
encript_tool encrypt "Hello, World!" -p mypassword -v
```

#### Decrypt a String

```bash
# From argument
encript_tool decrypt "encrypted_base64_string" -p mypassword

# From stdin
echo "encrypted_base64_string" | encript_tool decrypt -p mypassword
```

#### Encrypt a File

```bash
# Basic file encryption
encript_tool encrypt-file input.txt -p mypassword

# Specify output file
encript_tool encrypt-file input.txt -o encrypted.enc -p mypassword

# Delete original after encryption
encript_tool encrypt-file input.txt -p mypassword --delete-original

# Use streaming mode for large files
encript_tool encrypt-file largefile.zip -p mypassword --streaming
```

#### Decrypt a File

```bash
# Basic file decryption
encript_tool decrypt-file encrypted.enc -p mypassword

# Specify output file
encript_tool decrypt-file encrypted.enc -o output.txt -p mypassword

# Delete encrypted file after decryption
encript_tool decrypt-file encrypted.enc -p mypassword --delete-encrypted

# Use streaming mode for large files
encript_tool decrypt-file largefile.enc -p mypassword --streaming
```

### GUI Mode

Launch the GUI application:

```bash
# If built with GUI feature
encript_tool gui

# Or run the dedicated GUI binary
encript_tool_gui
```

The GUI provides an intuitive interface for:
- String encryption/decryption
- File encryption/decryption
- Real-time visualization of the encryption process

### Configuration Management

```bash
# Initialize default configuration file
encript_tool config init

# Show current configuration
encript_tool config show

# Display config file path
encript_tool config path

# Reset configuration to defaults
encript_tool config reset

# Use custom config file
encript_tool --config /path/to/config.toml encrypt "text" -p password
```

## Configuration

The configuration file is stored at `~/.config/encript_tool/config.toml` (Linux/macOS) or `%APPDATA%\encript_tool\config.toml` (Windows).

Example configuration:

```toml
version = "1.0"
default_format = "base64"
default_verbose = false
default_password_env = "CRYPT_PASSWORD"

[argon2]
memory_cost = 65536      # Memory usage in KB (64 MB)
time_cost = 3            # Number of iterations
parallelism = 4          # Number of parallel threads
```

### Argon2 Parameters

- **memory_cost**: Amount of memory used (in KiB). Higher values increase security but require more RAM
- **time_cost**: Number of iterations. Higher values increase security but take more time
- **parallelism**: Number of parallel threads. Should match your CPU core count

## Security Features

- **AES-256-GCM**: Industry-standard authenticated encryption providing both confidentiality and integrity
- **Argon2**: Memory-hard key derivation function resistant to GPU/ASIC attacks
- **Random Nonces**: Each encryption uses a unique 96-bit random nonce
- **Authenticated Encryption**: Built-in integrity verification prevents tampering
- **Secure Deletion**: Options to delete original files after encryption

## Building

```bash
# Build CLI only
cargo build --release

# Build with GUI
cargo build --release --features gui

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- encrypt "test" -p password -v
```

## Dependencies

Key dependencies:
- `aes-gcm` - AES-GCM encryption
- `argon2` - Argon2 key derivation
- `clap` - Command-line argument parsing
- `eframe` / `egui` - GUI framework (optional)
- `base64` - Base64 encoding/decoding

## License

This project is open source. Please add an appropriate license file.

## Security Considerations

- **Password Strength**: Use strong, unique passwords (minimum 12 characters recommended)
- **Key Storage**: Never store passwords in plain text or version control
- **Memory Security**: Sensitive data is not explicitly zeroed from memory
- **Side Channels**: This implementation is not hardened against side-channel attacks
- **Audit Status**: This tool has not undergone formal security audit

For production use cases requiring high security, consider:
- Using hardware security modules (HSM)
- Implementing additional key management practices
- Conducting security audits
- Following your organization's security policies

## Contributing

Contributions are welcome! Please ensure code follows Rust best practices and includes appropriate tests.

## Acknowledgments

Built with Rust and leveraging well-established cryptographic libraries from the RustCrypto project.
