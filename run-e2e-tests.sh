#!/bin/bash

echo "🤖 Claude's Automated Testing System"
echo "====================================="
echo ""
echo "This script will:"
echo "1. Verify dev server is running"
echo "2. Run automated browser tests"
echo "3. Capture screenshots at each step"
echo "4. Generate a test report"
echo ""

# Create test-results directory
mkdir -p test-results

# Check if dev server is running
echo "Checking if dev server is running on http://localhost:5173..."
if curl -s http://localhost:5173 > /dev/null; then
    echo "✅ Dev server is running"
else
    echo "❌ Dev server is not running!"
    echo "Please start it with: npm run dev"
    exit 1
fi

# Check if Ollama is running
echo "Checking if Ollama is running..."
if curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "✅ Ollama is running"
else
    echo "⚠️  Ollama is not running (execution mode won't work)"
    echo "Start it with: ./start_with_ollama.sh"
fi

echo ""
echo "🧪 Running automated tests..."
echo ""

# Run Playwright tests
npx playwright test tests/ui/e2e/execution-mode.spec.ts --reporter=list

echo ""
echo "📊 Test Results:"
echo "================"
echo ""

# Show test report
echo "HTML Report: file://$(pwd)/playwright-report/index.html"
echo "Screenshots: $(pwd)/test-results/"
echo ""

# List screenshots
echo "📸 Captured Screenshots:"
ls -lh test-results/*.png 2>/dev/null | awk '{print "  -", $9, "("$5")"}'

echo ""
echo "✨ Testing complete! Check the screenshots and HTML report for details."
echo ""
