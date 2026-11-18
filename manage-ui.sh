#!/bin/bash
# Marty UI Service Management Script
# Manages the UI dev server in a detached screen session

set -e

UI_DIR="/Volumes/Heart of Gold/Github/work/marty-ui/ui"
SCREEN_NAME="marty-ui"

case "${1:-}" in
  start)
    if screen -list | grep -q "$SCREEN_NAME"; then
      echo "✅ UI server is already running"
      screen -list | grep "$SCREEN_NAME"
    else
      echo "🚀 Starting UI server in screen session..."
      cd "$UI_DIR"
      screen -dmS "$SCREEN_NAME" bun run vite --host --mode tunnel
      sleep 3
      if screen -list | grep -q "$SCREEN_NAME"; then
        echo "✅ UI server started successfully"
        screen -list | grep "$SCREEN_NAME"
      else
        echo "❌ Failed to start UI server"
        exit 1
      fi
    fi
    ;;
    
  stop)
    echo "🛑 Stopping UI server..."
    if screen -list | grep -q "$SCREEN_NAME"; then
      screen -S "$SCREEN_NAME" -X quit
      echo "✅ UI server stopped"
    else
      echo "⚠️  UI server was not running"
    fi
    ;;
    
  restart)
    echo "🔄 Restarting UI server..."
    $0 stop
    sleep 2
    $0 start
    ;;
    
  status)
    if screen -list | grep -q "$SCREEN_NAME"; then
      echo "✅ UI server is running"
      screen -list | grep "$SCREEN_NAME"
      echo ""
      if lsof -i :3002 | grep -q LISTEN; then
        echo "✅ Port 3002 is listening"
      else
        echo "⚠️  Port 3002 is not listening (server may be starting)"
      fi
    else
      echo "❌ UI server is not running"
      exit 1
    fi
    ;;
    
  attach)
    if screen -list | grep -q "$SCREEN_NAME"; then
      echo "📎 Attaching to UI server (Press Ctrl+A then D to detach)..."
      screen -r "$SCREEN_NAME"
    else
      echo "❌ UI server is not running. Start it with: $0 start"
      exit 1
    fi
    ;;
    
  logs)
    if screen -list | grep -q "$SCREEN_NAME"; then
      echo "📋 Viewing UI server session (Press Ctrl+A then D to detach)..."
      screen -r "$SCREEN_NAME"
    else
      echo "❌ UI server is not running"
      exit 1
    fi
    ;;
    
  *)
    cat <<EOF
Marty UI Service Manager

Usage: $0 {start|stop|restart|status|attach|logs}

Commands:
  start    - Start the UI server in a detached screen session
  stop     - Stop the UI server
  restart  - Restart the UI server
  status   - Check if the UI server is running
  attach   - Attach to the UI server screen session (same as logs)
  logs     - View the UI server output (Ctrl+A D to detach)

Examples:
  $0 start           # Start the server
  $0 status          # Check if running
  $0 logs            # View output
  $0 restart         # Restart server

The UI will be accessible at:
  - Local: http://localhost:3002
  - Public: https://beta.elevenidllc.com

EOF
    ;;
esac
