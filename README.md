# Panda Cloud

File storage system that connects your S3 bucket to a web interface. Files upload and download directly between your browser and S3.

## What It Does

- Store and retrieve files using any S3-compatible storage service
- Multiple users, each with their own S3 credentials and bucket
- Files stream directly between browser and S3 (server only handles authentication and generates signed URLs)
- Preview images, PDFs, and videos in browser
- Admin panel for user management

## How It Works

The server doesn't store files. When you upload or download:

1. Browser asks server for a signed URL
2. Server generates a temporary URL with AWS Signature V4
3. Browser uploads/downloads directly to/from S3 using that URL
4. Server never touches the file data

This means no file size limits and no server storage needed.

## Requirements

- Nim compiler (version 1.6.0 or later)
- S3-compatible storage account (AWS S3, Tebi.io, MinIO, etc.)
- Access key, secret key, and bucket name from your S3 provider

## Installation

1. Install Nim if you don't have it
2. Clone this repository
3. Build the binary:
   ```bash
   chmod +x build.sh
   ./build.sh
   ```

## Configuration

Create a `users.txt` file with this format:
```
username:password:access_key:secret_key:bucket_name:endpoint:region
```

Example:
```
alice:secure_password:AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:my-bucket:s3.tebi.io:us-east-1
bob:another_password:AKIAI44QH8DHBEXAMPLE:je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY:bob-bucket:s3.amazonaws.com:us-west-2
```

Lines starting with `#` are comments.

The first time each user logs in, their plaintext password automatically converts to a hashed version for security.

## Admin User

Set admin username with environment variable:
```bash
export ADMIN_USERNAME=alice
```

If not set, defaults to "momo". The admin user can:
- View all users
- Add new users
- Update user credentials
- Delete users (except themselves)

Access admin panel at `/admin` or use `admin.` subdomain.

## Running

Start the server:
```bash
./panda_vault_v2
```

Server runs on port 5000 by default. Access at `http://localhost:5000`

## Port Configuration

The code has port settings in two places that don't match:
- Line 8: `port = Port(5000)`
- Line 3: Echo message says "PORT 9090"

The actual port is 5000. The echo message is wrong.

## Behind a Reverse Proxy

Example nginx configuration:
```nginx
server {
    listen 80;
    server_name cloud.example.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Features

- Passwords hashed with SHA-256 and random salt
- Session IDs generated with cryptographically secure random bytes
- Session timeout after 24 hours of inactivity
- AWS Signature V4 for all S3 requests
- Presigned URLs expire after 1 hour
- Admin functions require admin privileges

## API Endpoints

- `POST /api/login` - Authenticate user
- `GET /api/files?prefix=folder/` - List files and folders
- `POST /api/sign-upload` - Get URL for uploading
- `POST /api/delete` - Delete a file
- `POST /api/create-folder` - Create folder
- `GET /api/admin/users` - List users (admin only)
- `POST /api/admin/add-user` - Add user (admin only)
- `POST /api/admin/update-user` - Update user (admin only)
- `POST /api/admin/delete-user` - Delete user (admin only)

## S3 Compatibility

The code tries three different S3 API modes to work with different providers:
1. Modern S3 (list-type=2)
2. Legacy S3 (delimiter only)
3. Simple mode (prefix only)

It detects what works for your provider and remembers it.

## File Structure

- `panda_vault_v2.nim` - Main application (with numThreads = 1)
- `panda_new.nim` - Identical copy without numThreads setting
- `sqlite_auth_code.nim` - Alternative SQLite authentication (not used by default)
- `public/index.html` - Main user interface
- `public/admin.html` - Admin interface
- `public/performance.js` - Performance monitoring
- `users.txt` - User credentials database

## Development

Hot reload frontend changes without restart:
```bash
./hotdeploy.sh
```

The server reads static files from disk on each request, so HTML/CSS/JS changes apply immediately.

## Known Issues

1. Both `panda_vault_v2.nim` and `panda_new.nim` exist with nearly identical code
2. Port number mismatch in startup message
3. System time validation is strict (fails if year is outside 2020-2030 range)
4. `.gitignore` references "Baymax.txt" which suggests a private key was previously in the repo
5. License is set to "proprietary" in nimble file

## Binary Size

Compiled binary is approximately 1.5-2.8 MB depending on build settings and which version you compile.

## Memory Usage

Base memory usage around 10MB plus overhead for each active session.

## Monitoring

Performance metrics available via `/performance.js` endpoint.

## Cache

Server caches S3 list responses for 2 minutes to reduce API calls. Cache invalidates when you upload, delete, or create folders.

## Contributing

The codebase uses Nim language with the Jester web framework. Make sure changes work with both S3 and S3-compatible services.

## Security

A security audit has been performed on this codebase. See `SECURITY_FINDINGS.md` for details on identified issues and recommendations.

Key security considerations:
- Always set strong passwords for users
- Protect the `users.txt` file (chmod 600) - it contains AWS credentials
- Set `ADMIN_USERNAME` environment variable in production
- Use HTTPS in production with a reverse proxy
- Consider implementing rate limiting for production deployments
