#!/bin/bash
# 🔄 Sync script for Panda Cloud development

SERVER="baymax@163.123.236.154"
PORT="2026" 
KEY="../Baymax.txt"
REMOTE_PATH="/home/baymax/cloud"
LOCAL_PATH="."

echo "🐼 Panda Cloud Sync Options"
echo "=========================="
echo "1. Download from server (pull)"
echo "2. Upload to server (push)"  
echo "3. Bidirectional sync"
echo "4. Compare files"

read -p "Select option (1-4): " choice

case $choice in
    1)
        echo "📥 Downloading from server..."
        rsync -avz --progress -e "ssh -i $KEY -p $PORT" "$SERVER:$REMOTE_PATH/" "$LOCAL_PATH/"
        echo "✅ Download complete"
        ;;
    2)
        echo "📤 Uploading to server..."
        rsync -avz --progress -e "ssh -i $KEY -p $PORT" "$LOCAL_PATH/" "$SERVER:$REMOTE_PATH/"
        echo "✅ Upload complete"
        ;;
    3)
        echo "🔄 Bidirectional sync..."
        rsync -avz --progress -e "ssh -i $KEY -p $PORT" "$SERVER:$REMOTE_PATH/" "$LOCAL_PATH/"
        echo "✅ Sync complete"
        ;;
    4)
        echo "📊 Comparing files..."
        ssh -i "$KEY" -p "$PORT" "$SERVER" "cd $REMOTE_PATH && find . -name '*.nim' -o -name '*.html' -exec wc -l {} \;" > /tmp/remote_sizes
        find . -name '*.nim' -o -name '*.html' -exec wc -l {} \; > /tmp/local_sizes
        echo "Remote files:"
        cat /tmp/remote_sizes
        echo "Local files:"
        cat /tmp/local_sizes
        ;;
    *)
        echo "Invalid option"
        ;;
esac