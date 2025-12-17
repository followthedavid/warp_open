#!/bin/bash

# Warp Session Restore Script
# Imports old Warp AI conversations into Warp_Open with Ollama

set -e

BACKUP_DB="/Volumes/Applications/ReverseLab_Cleanup_Backup/Backups/warp_cleanup_backups/final_configs/dev.warp.Warp-Stable/warp.sqlite"
BACKUP_CONTEXT="/Volumes/Applications/ReverseLab_Cleanup_Backup/Backups/warp_cleanup_backups/final_configs/.warp_memory/current_context.json"
OUTPUT_DIR="$HOME/.warp_open/restored_sessions"
IMPORT_JSON="$HOME/.warp_open/import_sessions.json"

echo "🔄 Warp Session Restore Tool"
echo "=============================="
echo ""

# Check if backup database exists
if [ ! -f "$BACKUP_DB" ]; then
    echo "❌ Backup database not found at:"
    echo "   $BACKUP_DB"
    echo ""
    echo "Please ensure the backup volume is mounted:"
    echo "   /Volumes/Applications/ReverseLab_Cleanup_Backup"
    exit 1
fi

echo "✅ Found backup database"
echo "📊 Analyzing AI conversations..."

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Count AI conversations
AI_COUNT=$(sqlite3 "$BACKUP_DB" "SELECT COUNT(DISTINCT json_extract(ai_metadata, '$.conversation_id')) FROM blocks WHERE ai_metadata IS NOT NULL")
BLOCK_COUNT=$(sqlite3 "$BACKUP_DB" "SELECT COUNT(*) FROM blocks WHERE ai_metadata IS NOT NULL")

echo "   Found: $AI_COUNT unique AI conversations"
echo "   Total: $BLOCK_COUNT AI-related blocks"
echo ""

if [ "$AI_COUNT" -eq 0 ]; then
    echo "⚠️  No AI conversations found in backup"
    exit 0
fi

echo "📦 Extracting conversations..."

# Extract conversations grouped by conversation_id
sqlite3 "$BACKUP_DB" <<EOF > "$OUTPUT_DIR/conversations.json"
.mode json
SELECT
    json_extract(ai_metadata, '$.conversation_id') as conversation_id,
    json_extract(ai_metadata, '$.action_id') as action_id,
    stylized_command as command,
    stylized_output as output,
    pwd,
    completed_ts,
    start_ts,
    shell,
    user,
    host
FROM blocks
WHERE ai_metadata IS NOT NULL
ORDER BY start_ts ASC;
EOF

# Extract unique conversations for tab creation
sqlite3 "$BACKUP_DB" <<EOF > "$OUTPUT_DIR/conversation_list.json"
.mode json
SELECT DISTINCT
    json_extract(ai_metadata, '$.conversation_id') as id,
    MIN(start_ts) as first_message,
    MAX(completed_ts) as last_message,
    COUNT(*) as message_count
FROM blocks
WHERE ai_metadata IS NOT NULL
GROUP BY json_extract(ai_metadata, '$.conversation_id')
ORDER BY MIN(start_ts) DESC;
EOF

echo "✅ Extracted conversation data"
echo ""

# Create importable format for Warp_Open
cat > "$IMPORT_JSON" <<EOJSON
{
  "version": "1.0",
  "source": "warp_backup",
  "imported_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "conversations": $(cat "$OUTPUT_DIR/conversation_list.json"),
  "total_conversations": $AI_COUNT,
  "total_blocks": $BLOCK_COUNT
}
EOJSON

echo "📋 Created import manifest:"
echo "   $IMPORT_JSON"
echo ""
echo "📂 Conversation data saved to:"
echo "   $OUTPUT_DIR/"
echo ""

# Generate TypeScript import code
cat > "$OUTPUT_DIR/import_code.ts" <<'EOTS'
// Warp Session Import Code
// Drop this into your Vue app or run as a script

import { useAI } from '@/composables/useAI';
import { useTabs } from '@/composables/useTabs';
import { readFileSync } from 'fs';
import { v4 as uuidv4 } from 'uuid';

interface ImportedConversation {
  id: string;
  first_message: string;
  last_message: string;
  message_count: number;
}

interface ImportManifest {
  version: string;
  source: string;
  imported_at: string;
  conversations: ImportedConversation[];
  total_conversations: number;
  total_blocks: number;
}

export async function importWarpSessions() {
  const { createAITab } = useTabs();
  const { getSession, addMessage } = useAI();

  // Load import manifest
  const manifest: ImportManifest = JSON.parse(
    readFileSync(process.env.HOME + '/.warp_open/import_sessions.json', 'utf-8')
  );

  const conversations = JSON.parse(
    readFileSync(process.env.HOME + '/.warp_open/restored_sessions/conversations.json', 'utf-8')
  );

  console.log(`Importing ${manifest.total_conversations} conversations...`);

  // Group messages by conversation
  const conversationMap = new Map<string, any[]>();
  for (const block of conversations) {
    if (!conversationMap.has(block.conversation_id)) {
      conversationMap.set(block.conversation_id, []);
    }
    conversationMap.get(block.conversation_id)!.push(block);
  }

  // Create tabs for each conversation
  let imported = 0;
  for (const [convId, messages] of conversationMap.entries()) {
    // Create new AI tab
    const tab = createAITab(`Restored: ${new Date(messages[0].start_ts).toLocaleDateString()}`);

    // Import messages
    for (const msg of messages) {
      // User message (command)
      if (msg.command) {
        addMessage(tab.id, {
          role: 'user',
          content: msg.command,
        });
      }

      // AI message (output)
      if (msg.output) {
        addMessage(tab.id, {
          role: 'assistant',
          content: msg.output,
        });
      }
    }

    imported++;
    console.log(`Imported conversation ${imported}/${manifest.total_conversations}: ${convId}`);
  }

  console.log(`✅ Successfully imported ${imported} conversations`);
  return imported;
}
EOTS

echo "💡 To import into your app, you can:"
echo ""
echo "   Option 1: Manual Review"
echo "   ------------------------"
echo "   1. Open: $OUTPUT_DIR/conversations.json"
echo "   2. Review the extracted conversations"
echo "   3. Manually recreate important ones in AI tabs"
echo ""
echo "   Option 2: Programmatic Import (Advanced)"
echo "   ----------------------------------------"
echo "   1. See: $OUTPUT_DIR/import_code.ts"
echo "   2. Integrate into your Vue app"
echo "   3. Call importWarpSessions() from DevTools"
echo ""

# Create summary report
cat > "$OUTPUT_DIR/RESTORE_REPORT.md" <<EOREPORT
# Warp Session Restore Report

**Date:** $(date)
**Source:** $BACKUP_DB
**Destination:** $OUTPUT_DIR

## Summary

- **Total AI Conversations:** $AI_COUNT
- **Total AI Blocks:** $BLOCK_COUNT
- **Earliest Message:** $(sqlite3 "$BACKUP_DB" "SELECT MIN(start_ts) FROM blocks WHERE ai_metadata IS NOT NULL")
- **Latest Message:** $(sqlite3 "$BACKUP_DB" "SELECT MAX(completed_ts) FROM blocks WHERE ai_metadata IS NOT NULL")

## Files Created

1. \`conversations.json\` - Full conversation data
2. \`conversation_list.json\` - Conversation metadata
3. \`import_code.ts\` - TypeScript import helper
4. \`../import_sessions.json\` - Import manifest

## Conversation Distribution

\`\`\`
$(sqlite3 "$BACKUP_DB" "
SELECT
    json_extract(ai_metadata, '$.conversation_phase') as phase,
    COUNT(DISTINCT json_extract(ai_metadata, '$.conversation_id')) as count
FROM blocks
WHERE ai_metadata IS NOT NULL
GROUP BY phase
ORDER BY count DESC
")
\`\`\`

## Top 10 Most Active Conversations

\`\`\`
$(sqlite3 "$BACKUP_DB" "
SELECT
    json_extract(ai_metadata, '$.conversation_id') as id,
    COUNT(*) as messages,
    MIN(start_ts) as started,
    MAX(completed_ts) as ended
FROM blocks
WHERE ai_metadata IS NOT NULL
GROUP BY json_extract(ai_metadata, '$.conversation_id')
ORDER BY COUNT(*) DESC
LIMIT 10
")
\`\`\`

## Next Steps

1. Review \`conversations.json\` to see your old AI chats
2. Decide which conversations to restore
3. Either manually recreate them in Warp_Open AI tabs
4. Or use the provided TypeScript import code

---

*Generated by restore_sessions.sh*
EOREPORT

echo "📊 Summary report created:"
echo "   $OUTPUT_DIR/RESTORE_REPORT.md"
echo ""
echo "✅ Session restore complete!"
echo ""
echo "🎯 Next: Review $OUTPUT_DIR/RESTORE_REPORT.md"
