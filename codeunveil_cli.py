import sys
import subprocess
import os

def main():
    """CLI Entry point for CodeUnveil v1.0.0."""
    print("Starting CodeUnveil v1.0.0...")
    
    # Resolve the path to app.py relative to this CLI script
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    
    if not os.path.exists(app_path):
        print(f"Error: Could not locate app.py at {app_path}", file=sys.stderr)
        sys.exit(1)
        
    try:
        # Launch Streamlit as a subprocess
        subprocess.run([sys.executable, "-m", "streamlit", "run", app_path], check=True)
    except KeyboardInterrupt:
        print("\nCodeUnveil shutdown requested.")
    except subprocess.CalledProcessError as e:
        print(f"\nCodeUnveil exited with error: {e}", file=sys.stderr)
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
