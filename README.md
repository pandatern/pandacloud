# 🐼 Panda Cloud

A lightweight, secure file management system with direct S3 streaming capabilities.

## Features

- 🔐 **Multi-user authentication** with individual S3 credentials
- 📁 **Universal file preview** - supports images, PDFs, videos, and more
- ☁️ **Direct S3 streaming** - unlimited file sizes, zero server storage
- 🎨 **Clean interface** - professional white/black theme
- 🚀 **Lightweight** - 972KB binary, minimal resource usage
- 🔒 **Secure** - AWS Signature V4 authentication, presigned URLs

## Architecture

Panda Cloud uses a smart presigned URL architecture:
- Backend only handles metadata and URL signing
- File uploads/downloads go directly to S3
- No file data touches the server
- Unlimited concurrent operations

## Quick Start

### Requirements
- Nim compiler
- S3-compatible storage (AWS S3, Tebi.io, etc.)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/pandatern/cloud.git
cd cloud
```

2. Build for production:
```bash
chmod +x build.sh
./build.sh
```

3. Configure users in `users.txt`:
```bash
# Format: username:password:access_key:secret_key:bucket:endpoint:region
demo:demo123:your_access_key:your_secret_key:your_bucket:s3.tebi.io:us-east-1
```

4. Start the server:
```bash
./panda_vault_v2
```

5. Access at `http://localhost:8082`

## Multi-User Setup

Add multiple users by adding more environment variables:

```bash
# User 1
USER_alice_PASSWORD="alice123"
USER_alice_AWS_ACCESS_KEY_ID="alice_key"
USER_alice_AWS_SECRET_ACCESS_KEY="alice_secret"
USER_alice_AWS_S3_BUCKET="alice_bucket"

# User 2  
USER_bob_PASSWORD="bob456"
USER_bob_AWS_ACCESS_KEY_ID="bob_key"
USER_bob_AWS_SECRET_ACCESS_KEY="bob_secret"
USER_bob_AWS_S3_BUCKET="bob_bucket"
```

## Production Deployment

### Quick Deployment
```bash
# Build and start
./build.sh
./panda_vault_v2 &

# Hot deploy frontend updates (without restart)
./hotdeploy.sh
```

### With Nginx (Recommended)

1. Run Panda Cloud:
```bash
tmux new-session -d -s panda_cloud './panda_vault_v2'
```

2. Configure Nginx:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8082;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## API Endpoints

- `POST /api/login` - User authentication
- `GET /api/files` - List files  
- `POST /api/sign-upload` - Generate upload URLs
- `POST /api/delete` - Delete files

## Technical Details

- **Language**: Nim + Jester web framework
- **Frontend**: Vanilla JS + TailwindCSS
- **Storage**: S3-compatible (AWS S3, Tebi.io, MinIO, etc.)
- **Authentication**: Multi-user with environment-based credentials
- **Security**: AWS Signature V4, secure session management

## Performance

- **Binary size**: 972KB
- **Memory usage**: ~10MB base + sessions
- **Concurrent uploads**: Unlimited (direct to S3)
- **File size limit**: None (streaming architecture)
- **Throughput**: Limited only by S3 and network bandwidth

## License

MIT License - see LICENSE file for details.

## Contributing

Pull requests welcome! Please ensure code follows the existing style and includes appropriate tests.