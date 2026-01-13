#!/bin/bash

# 🐼 Panda Cloud Production Build Script

echo "🐼 Building Panda Cloud for production..."

# Check if Nim is installed
if ! command -v nim &> /dev/null; then
    echo "❌ Nim compiler not found. Please install Nim first."
    exit 1
fi

# Build the application
echo "🔧 Compiling Nim application..."
nim c -d:release --opt:speed panda_vault_v2.nim

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo "📦 Binary size: $(du -h panda_vault_v2 | cut -f1)"
    echo ""
    echo "🚀 To start the server:"
    echo "   ./panda_vault_v2"
    echo ""
    echo "🌐 Server will be available at:"
    echo "   http://localhost:5000"
else
    echo "❌ Build failed!"
    exit 1
fi

# Download production assets if not present
if [ ! -f "public/tailwind.css" ] || [ ! -s "public/tailwind.css" ]; then
    echo "📥 Downloading Tailwind CSS for production..."
    curl -s -o public/tailwind.css "https://cdn.tailwindcss.com/3.4.0" || {
        echo "⚠️  Warning: Could not download Tailwind CSS. Will fallback to CDN."
    }
fi

# Create favicon if not present
if [ ! -f "public/favicon.ico" ]; then
    echo "🎨 Creating favicon..."
    # Create a minimal ICO file (16x16 transparent)
    echo -ne '\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x16\x00\x00\x00' > public/favicon.ico
fi

echo ""
echo "✅ Production build complete!"
echo "📝 Make sure to configure users.txt before starting the server."