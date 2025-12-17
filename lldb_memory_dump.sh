#!/bin/bash
# Memory Dumping Script for ChatGPT Responses
# This searches process memory for response text

PID=$(pgrep ChatGPT | head -1)

if [ -z "$PID" ]; then
    echo "ERROR: ChatGPT not running"
    exit 1
fi

echo "==========================================="
echo "ChatGPT Memory Dumping"
echo "==========================================="
echo "PID: $PID"
echo ""
echo "This will attach lldb and search memory for text."
echo "After lldb attaches, send a ChatGPT message containing"
echo "the word 'MEMORYDUMP' so we can find it in memory."
echo ""
echo "Commands you can run in lldb:"
echo "  memory find -s 'MEMORYDUMP' -- 0x0 0xFFFFFFFFFFFFFFFF"
echo "  memory read 0xADDRESS"
echo "  detach"
echo "  quit"
echo ""
echo "Press Enter to attach lldb..."
read

lldb -p $PID
