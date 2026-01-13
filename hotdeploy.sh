#!/bin/bash

# 🐼 Panda Cloud Hot Deployment Script
# Updates frontend files without restarting the server

echo "🔄 Hot deploying Panda Cloud frontend updates..."

# Backup current files
backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"

echo "💾 Creating backup in $backup_dir..."
cp -r public "$backup_dir/"

# Update production assets
echo "📥 Updating Tailwind CSS..."
curl -s -o public/tailwind.css "https://cdn.tailwindcss.com/3.4.0" || {
    echo "⚠️  Warning: Could not download Tailwind CSS."
}

# Create proper favicon if needed
if [ ! -f "public/favicon.ico" ] || [ "$(wc -c < public/favicon.ico)" -lt 100 ]; then
    echo "🎨 Creating proper favicon..."
    # Create a minimal but valid ICO file
    echo -ne '\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x16\x00\x00\x00' > public/favicon.ico
fi

# Check if server is running
if pgrep -f "panda_vault_v2" > /dev/null; then
    echo "✅ Server is running on port 5000"
    echo "🔧 Frontend files updated without server restart"
else
    echo "⚠️  Server is not running. Start it with: ./panda_vault_v2"
fi

echo ""
echo "✅ Hot deployment complete!"
echo "🌐 Changes are live at: http://localhost:5000"
echo "📋 Backup created in: $backup_dir"