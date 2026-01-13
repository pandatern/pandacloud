#!/bin/bash

# 🔒 Panda Cloud Security Check Script
# Run this script to verify security configuration

echo "🔒 Panda Cloud Security Audit"
echo "=============================="
echo ""

ISSUES_FOUND=0

# Check 1: File permissions on users.txt
echo "1. Checking users.txt file permissions..."
if [ -f "users.txt" ]; then
    PERMS=$(stat -c "%a" users.txt)
    if [ "$PERMS" = "600" ]; then
        echo "   ✅ users.txt permissions are secure ($PERMS)"
    else
        echo "   ❌ SECURITY ISSUE: users.txt permissions are $PERMS (should be 600)"
        echo "      Fix with: chmod 600 users.txt"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    echo "   ⚠️  users.txt not found"
fi

# Check 2: Admin username configuration
echo ""
echo "2. Checking admin username configuration..."
if [ -n "$ADMIN_USERNAME" ]; then
    echo "   ✅ ADMIN_USERNAME environment variable is set"
else
    echo "   ❌ SECURITY ISSUE: ADMIN_USERNAME not set, using default 'momo'"
    echo "      Fix with: export ADMIN_USERNAME='your_secure_admin_name'"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

# Check 3: Running as root
echo ""
echo "3. Checking user privileges..."
if [ "$EUID" -eq 0 ]; then
    echo "   ❌ SECURITY ISSUE: Running as root user"
    echo "      Recommendation: Create dedicated user for Panda Cloud"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo "   ✅ Not running as root user"
fi

# Check 4: Git ignore status
echo ""
echo "4. Checking git ignore configuration..."
if [ -f ".gitignore" ]; then
    if grep -q "users.txt" .gitignore; then
        echo "   ✅ users.txt is properly gitignored"
    else
        echo "   ❌ SECURITY ISSUE: users.txt not in .gitignore"
        echo "      This file contains sensitive credentials!"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    echo "   ⚠️  .gitignore file not found"
fi

# Check 5: Default port configuration
echo ""
echo "5. Checking port configuration..."
if grep -q "port = Port(5000)" panda_vault_v2.nim; then
    echo "   ✅ Using default port 5000"
    echo "      Recommendation: Use reverse proxy (nginx) for production"
else
    echo "   ⚠️  Non-standard port configuration detected"
fi

# Check 6: SSL/HTTPS configuration
echo ""
echo "6. Checking SSL/HTTPS configuration..."
if netstat -tuln 2>/dev/null | grep -q ":443 "; then
    echo "   ✅ HTTPS port 443 is active (likely reverse proxy)"
elif netstat -tuln 2>/dev/null | grep -q ":80 "; then
    echo "   ⚠️  Only HTTP port 80 active - HTTPS recommended for production"
else
    echo "   ⚠️  No web server detected on standard ports"
fi

# Check 7: Backup files present
echo ""
echo "7. Checking for backup files..."
if ls users.txt.bak 2>/dev/null || ls users.txt~ 2>/dev/null; then
    echo "   ❌ SECURITY ISSUE: Backup files found with potentially sensitive data"
    echo "      Remove backup files: rm users.txt.bak users.txt~"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo "   ✅ No insecure backup files found"
fi

# Check 8: Log file permissions
echo ""
echo "8. Checking log file security..."
if [ -f "server.log" ]; then
    LOG_PERMS=$(stat -c "%a" server.log 2>/dev/null)
    if [ "$LOG_PERMS" = "600" ] || [ "$LOG_PERMS" = "640" ]; then
        echo "   ✅ Log file permissions are secure ($LOG_PERMS)"
    else
        echo "   ⚠️  Log file permissions: $LOG_PERMS (consider 600 or 640)"
    fi
else
    echo "   ✅ No server.log file found"
fi

# Check 9: Process security
echo ""
echo "9. Checking running processes..."
if pgrep -f "panda_vault_v2" >/dev/null; then
    PANDA_USER=$(ps -o user= -p $(pgrep -f "panda_vault_v2"))
    echo "   ✅ Panda Cloud is running as user: $PANDA_USER"
else
    echo "   ⚠️  Panda Cloud is not currently running"
fi

# Final summary
echo ""
echo "=============================="
if [ $ISSUES_FOUND -eq 0 ]; then
    echo "🎉 Security Audit Complete: No critical issues found!"
    echo ""
    echo "📋 Production Readiness Checklist:"
    echo "   □ Set up HTTPS/SSL certificates"
    echo "   □ Configure firewall rules"
    echo "   □ Set up log monitoring"
    echo "   □ Implement backup strategy"
    echo "   □ Configure rate limiting (nginx)"
    echo "   □ Set up security monitoring"
else
    echo "⚠️  Security Audit Complete: $ISSUES_FOUND issue(s) found"
    echo ""
    echo "🔧 Please address the issues above before production deployment"
fi
echo ""
echo "📖 For detailed security configuration, see SECURITY.md"
echo "=============================="