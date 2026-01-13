# Panda Cloud

A web interface for managing files in S3-compatible storage. Users upload and download files directly to/from S3 buckets using presigned URLs. The server only handles authentication and URL generation.

## What It Does

This is a file manager for S3 storage. Each user has their own S3 credentials and bucket. The application:

1. Authenticates users with username/password
2. Generates presigned S3 URLs for file operations
3. Provides a web interface to browse, upload, download, and delete files
4. Supports folder navigation within S3 buckets

Files never pass through the server - they go directly between the browser and S3.

## Requirements

- Nim compiler (to build the server)
- S3-compatible storage account (AWS S3, Tebi.io, MinIO, etc.)
- S3 access keys for each user

## Setup

1. Install Nim compiler if you don't have it

2. Build the server:
```bash
chmod +x build.sh
./build.sh
```

3. Configure user credentials in `users.txt`:

Copy the example file:
```bash
cp users.txt.example users.txt
```

Then edit `users.txt` and add your credentials:
```
# Format: username:password:access_key:secret_key:bucket:endpoint:region
alice:her_password:AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:alice-bucket:s3.amazonaws.com:us-east-1
```

**Important:** Set proper file permissions:
```bash
chmod 600 users.txt
```

4. Start the server:
```bash
./panda_vault_v2
```

Server runs on port 5000 by default.

## Multi-User Configuration

Add one line per user in `users.txt`. Each user gets:
- Their own username/password
- Their own S3 access key and secret key  
- Their own S3 bucket
- Optional: custom endpoint and region

The first user matching the `ADMIN_USERNAME` environment variable gets admin privileges (can manage other users).

## Security Notes

1. **Never commit `users.txt` with real credentials** - it's gitignored by default
2. **Use strong passwords** - they're hashed with SHA256
3. **Set file permissions**: `chmod 600 users.txt`
4. **Use HTTPS in production** - set up nginx or similar reverse proxy
5. **Rotate S3 keys regularly**
6. **Set admin username**: `export ADMIN_USERNAME="your_admin_name"` (default is "momo")

See `SECURITY.md` for detailed security configuration.

## Production Deployment

Use a reverse proxy like nginx:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Add SSL/TLS with Let's Encrypt or your certificate provider.

## Admin Panel

Access at `/admin` or `admin.your-domain.com`. Admin users can:
- View all users
- Add new users
- Update user credentials
- Delete users (except themselves)

## API

The server provides these endpoints:

- `POST /api/login` - Authenticate user
- `GET /api/files?prefix=folder/` - List files in folder
- `POST /api/sign-upload` - Get presigned URL for upload
- `POST /api/delete` - Delete file
- `POST /api/create-folder` - Create folder
- Admin endpoints at `/api/admin/*`

## How It Works

1. User logs in with username/password
2. Server validates credentials and creates session
3. User requests file list - server queries S3 and returns metadata
4. User uploads file - server generates presigned PUT URL, browser uploads directly to S3
5. User downloads file - server generates presigned GET URL, browser downloads directly from S3
6. User deletes file - server sends DELETE request to S3

The server never handles file contents, only metadata and URL signing.

## Technical Stack

- Backend: Nim language with Jester web framework
- Frontend: Vanilla JavaScript with Tailwind CSS
- Storage: Any S3-compatible service
- Auth: Username/password with SHA256 hashing
- Sessions: In-memory with 24-hour timeout

## Building

The build process compiles the Nim code and bundles static assets:

```bash
./build.sh          # Production build with optimizations
```

Binary size is about 3MB. Memory usage is around 10-20MB depending on active sessions.

## License

MIT License