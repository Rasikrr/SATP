#!/bin/bash

echo "=========================================="
echo "SATP Protocol Web Demonstration"
echo "=========================================="
echo ""
echo "Choose demonstration mode:"
echo ""
echo "1) REAL MODE - Run actual C++ client and server"
echo "   (Recommended for technical demo)"
echo ""
echo "2) REAL MODE + File Logs - Save all logs to files"
echo "   (Best for debugging and presentation)"
echo ""
echo "3) MOCK MODE - Simulated visualization only"
echo "   (Faster, no C++ dependencies)"
echo ""
read -p "Enter choice [1, 2 or 3]: " choice

echo ""

case $choice in
    1)
        echo "🚀 Starting REAL MODE..."
        echo "This will launch actual C++ SATP server and client"
        echo "Logs visible in terminal only"
        echo ""
        python3 app_real.py
        ;;
    2)
        echo "🚀 Starting REAL MODE with File Logging..."
        echo "This will launch actual C++ SATP server and client"
        echo "Logs will be saved to web_demo/logs/ directory"
        echo ""
        python3 app_real_with_logs.py
        ;;
    3)
        echo "🎨 Starting MOCK MODE..."
        echo "This will show simulated protocol visualization"
        echo ""
        python3 app.py
        ;;
    *)
        echo "❌ Invalid choice. Please run again and select 1, 2 or 3."
        exit 1
        ;;
esac
