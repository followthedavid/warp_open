# Quick Start Guide - Warp Phase 1-6 Bundle

## 🚀 Ready to Run in 3 Steps

### Step 1: Navigate to Bundle
```bash
cd /Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/warp_phase1_6_bundle
```

### Step 2: Generate Test Database (First Time Only)
```bash
python3 generate_phase1_6_db.py
```

Expected output:
```
Database 'phase1_6_test.db' created with Phase 1–6 test data.
```

### Step 3: Run Automated Tests
```bash
./run_phase1_6_auto_live.sh
```

The script will:
- ✅ Clean up any previous instances
- ✅ Launch the dashboard in your browser
- ✅ Show real-time Phase 1-6 execution
- ✅ Display event timeline visualization

## 🎯 What You Get

### Live Dashboard Features
- **Real-time Event Log** - See every phase execution as it happens
- **Interactive Timeline** - Visual representation of event distribution
- **One-Click Testing** - Start Phase 1-6 tests with a single button
- **Auto-Scrolling** - Latest events always visible

### Modes of Operation

#### 1. Standalone Mode (No Tauri Required)
Open `batch6_dashboard/index.html` directly in your browser:
```bash
open batch6_dashboard/index.html
```
Click "Run Full Phase 1-6 Test" to see simulated events.

#### 2. Integrated Mode (With Tauri)
The script automatically detects and uses Tauri if available at:
```
/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src-tauri
```

## 📊 Database Inspection

View the test data:
```bash
sqlite3 phase1_6_test.db
```

Useful queries:
```sql
-- List all tables
.tables

-- View batches
SELECT * FROM batches;

-- Check agents
SELECT name, status FROM agents;

-- View Phase 6 plans
SELECT * FROM plans WHERE phase = 6;

-- Recent telemetry
SELECT ts, tool, command FROM telemetry ORDER BY ts DESC LIMIT 5;
```

## 🔍 Monitoring

### View Live Logs
```bash
tail -f /tmp/warp_phase1_6_auto.log
```

### Dashboard Location
```
/tmp/warp_phase1_6_live.html
```

## 🛠 Customization

### Change Tauri App Location
```bash
export APP_DIR=/custom/path/to/src-tauri
./run_phase1_6_auto_live.sh
```

### Use Custom Database
```bash
export DB_PATH=/custom/path/database.db
./run_phase1_6_auto_live.sh
```

## 📦 Bundle Contents

```
warp_phase1_6_bundle/
├── batch6_dashboard/
│   ├── index.html          # Dashboard UI
│   ├── style.css           # Matrix-style theme
│   └── timeline.js         # Timeline visualization
├── generate_phase1_6_db.py # Database generator
├── run_phase1_6_auto_live.sh # Test runner
├── README.md               # Full documentation
├── LICENSE                 # MIT License
└── QUICKSTART.md          # This file
```

## ✅ Verification Checklist

After running the scripts, you should see:

- [ ] Database file: `phase1_6_test.db` (Created)
- [ ] Dashboard opens in browser automatically
- [ ] "Run Full Phase 1-6 Test" button visible
- [ ] Timeline visualization shows at bottom
- [ ] Events appear in log with timestamps
- [ ] Log file exists: `/tmp/warp_phase1_6_auto.log`

## 🐛 Troubleshooting

### Database Won't Create
```bash
# Check Python version (needs 3.6+)
python3 --version

# Reinstall if needed
rm phase1_6_test.db
python3 generate_phase1_6_db.py
```

### Dashboard Won't Open
```bash
# Manual open
open /tmp/warp_phase1_6_live.html

# Or open directly from bundle
open batch6_dashboard/index.html
```

### No Events Showing
1. Check browser console (F12) for JavaScript errors
2. Verify timeline.js is loading correctly
3. Try standalone mode first to test dashboard

## 🎓 Next Steps

1. **Read Full Documentation**: See `README.md` for advanced features
2. **Integrate with Tauri**: Add backend commands for real Phase 1-6 execution
3. **Customize Dashboard**: Modify `batch6_dashboard/` files to fit your needs
4. **Export Data**: Use SQLite queries to analyze test results

## 📞 Support

- Check `README.md` for comprehensive documentation
- Inspect logs at `/tmp/warp_phase1_6_auto.log`
- Test standalone mode first: `open batch6_dashboard/index.html`

---

**Ready to test?** Run `./run_phase1_6_auto_live.sh` now! 🚀
