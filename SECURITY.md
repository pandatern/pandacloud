# 🔒 Panda Cloud Security Configuration Guide

## Critical Security Requirements

### 1. Environment Variables (REQUIRED)
```bash
# Set admin username (do NOT use default "momo")
export ADMIN_USERNAME="your_secure_admin_username"

# Optional: Set custom port
export PANDA_PORT="5000"
```

### 2. File Permissions (CRITICAL)
```bash
# Secure the user credentials file
chmod 600 users.txt

# Ensure only owner can access the application directory
chmod 700 /path/to/pandacloud/

# Secure the application binary
chmod 755 panda_vault_v2
```

### 3. Firewall Configuration
```bash
# Only allow necessary ports
sudo ufw allow 5000/tcp
sudo ufw enable

# For production with nginx reverse proxy:
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 5000/tcp  # Block direct access to app
```

### 4. Production Deployment Checklist

#### ✅ Security Hardening
- [ ] Set `ADMIN_USERNAME` environment variable
- [ ] Set `users.txt` permissions to 600
- [ ] Use HTTPS (nginx/Apache reverse proxy)
- [ ] Implement rate limiting (nginx/fail2ban)
- [ ] Regular security updates
- [ ] Monitor logs for suspicious activity

#### ✅ Credential Management
- [ ] Use strong AWS credentials
- [ ] Rotate AWS keys regularly
- [ ] Use IAM policies to limit S3 bucket access
- [ ] Never commit users.txt to version control
- [ ] Backup users.txt securely (encrypted)

#### ✅ Network Security
- [ ] Use firewall rules
- [ ] Run behind reverse proxy (nginx)
- [ ] Enable SSL/TLS certificates
- [ ] Consider VPN for admin access
- [ ] Regular network security scans

#### ✅ Application Security
- [ ] Disable debug endpoints in production
- [ ] Monitor failed login attempts
- [ ] Implement session persistence if needed
- [ ] Regular application updates
- [ ] Security audit logs

### 5. Nginx Reverse Proxy Configuration (Recommended)

```nginx
# /etc/nginx/sites-available/pandacloud
server {
    listen 80;
    server_name your-domain.com;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    }
    
    location /api/login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://localhost:5000;
        # ... same proxy headers as above
    }
    
    location /api/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://localhost:5000;
        # ... same proxy headers as above
    }
    
    # Block access to debug endpoints in production
    location /api/debug/ {
        deny all;
        return 403;
    }
}
```

### 6. SSL/TLS Configuration (REQUIRED for Production)

```bash
# Install certbot for Let's Encrypt
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### 7. Monitoring and Logging

```bash
# Monitor failed logins
tail -f server.log | grep "Invalid Password"

# Monitor suspicious activity
tail -f /var/log/nginx/access.log | grep -E "(40[0-9]|50[0-9])"

# Set up log rotation
sudo logrotate /etc/logrotate.d/pandacloud
```

### 8. Backup Strategy

```bash
#!/bin/bash
# backup_pandacloud.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/secure/backups/pandacloud"

# Create encrypted backup of users.txt
gpg --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 \
    --s2k-digest-algo SHA512 --s2k-count 65536 \
    --symmetric --output "$BACKUP_DIR/users_$DATE.txt.gpg" users.txt

# Backup application files
tar -czf "$BACKUP_DIR/pandacloud_$DATE.tar.gz" \
    panda_vault_v2 panda_vault_v2.nim public/ *.sh

echo "✅ Backup completed: $BACKUP_DIR/"
```

### 9. Security Monitoring Script

```bash
#!/bin/bash
# security_check.sh

echo "🔒 Panda Cloud Security Check"
echo "=============================="

# Check file permissions
echo "📁 File Permissions:"
ls -la users.txt
ls -la panda_vault_v2

# Check for default admin username
if grep -q "ADMIN_USERNAME.*momo" panda_vault_v2.nim; then
    echo "⚠️  WARNING: Default admin username detected. Set ADMIN_USERNAME env var!"
fi

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  WARNING: Running as root. Use dedicated user instead."
fi

# Check if users.txt is in git
if git check-ignore users.txt >/dev/null 2>&1; then
    echo "✅ users.txt is properly gitignored"
else
    echo "❌ CRITICAL: users.txt is NOT gitignored!"
fi

echo "=============================="
echo "🔒 Security check complete"
```

## Security Best Practices Summary

1. **Never use default credentials**
2. **Always use HTTPS in production**
3. **Set proper file permissions**
4. **Implement rate limiting**
5. **Monitor logs regularly**
6. **Keep credentials separate from code**
7. **Regular security updates**
8. **Backup strategy with encryption**
9. **Network security (firewall/VPN)**
10. **Regular security audits**

## Emergency Security Response

If you suspect a security breach:

1. **Immediate Actions:**
   ```bash
   # Stop the service
   sudo systemctl stop pandacloud
   
   # Check logs for suspicious activity
   grep -i "failed\|error\|unauthorized" server.log
   
   # Rotate all credentials
   # Change admin password
   # Rotate AWS keys
   ```

2. **Investigation:**
   - Review access logs
   - Check for unauthorized file access
   - Verify S3 bucket activity
   - Check system logs

3. **Recovery:**
   - Update all passwords
   - Rotate AWS credentials
   - Review user access
   - Update security configurations
   - Restart with new credentials

Remember: **Security is an ongoing process, not a one-time setup!**