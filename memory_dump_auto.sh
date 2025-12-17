#!/bin/bash
# Automated Memory Dump Script

PID=$(pgrep ChatGPT | head -1)
DUMP_FILE="/tmp/chatgpt_memory_dump.txt"

if [ -z "$PID" ]; then
    echo "ERROR: ChatGPT not running"
    exit 1
fi

echo "==========================================="
echo "ChatGPT Automated Memory Dump"
echo "==========================================="
echo "PID: $PID"
echo "Dump file: $DUMP_FILE"
echo ""

echo "[1/4] Dumping process memory regions..."
echo "This will take 30-60 seconds..."

# Use lldb to dump memory
cat > /tmp/lldb_dump.txt << 'EOF'
memory region
heap list
detach
quit
EOF

lldb -p $PID -s /tmp/lldb_dump.txt > $DUMP_FILE 2>&1

echo "[2/4] Extracting strings from memory..."
# Try to extract strings directly from process memory
sudo strings -n 20 /proc/$PID/mem 2>/dev/null | head -10000 >> $DUMP_FILE 2>&1 || true

# Alternative: use vmmap
echo "[3/4] Getting memory map..."
sudo vmmap $PID >> $DUMP_FILE 2>&1

echo "[4/4] Searching for patterns..."
echo ""
echo "Searching for 'MEMORYDUMP'..."
grep -a -C 5 "MEMORYDUMP" $DUMP_FILE 2>/dev/null || echo "  Not found"

echo ""
echo "Searching for 'assistant'..."
grep -a -C 5 "assistant" $DUMP_FILE 2>/dev/null | head -20 || echo "  Not found"

echo ""
echo "Searching for common response words..."
grep -a -E "(Hello|I'm|response|message)" $DUMP_FILE 2>/dev/null | head -20 || echo "  Not found"

echo ""
echo "==========================================="
echo "Dump complete: $DUMP_FILE"
echo "Use: cat $DUMP_FILE | grep -a 'PATTERN'"
echo "==========================================="
