import uvicorn
import argparse
from server import app

def main():
    parser = argparse.ArgumentParser(description='Musical Jam Session Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind the server to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print(f"Starting Musical Jam Session Server on {args.host}:{args.port}")
    print("Press Ctrl+C to stop the server")
    
    uvicorn.run(app, host=args.host, port=args.port, log_level="debug" if args.debug else "info")

if __name__ == "__main__":
    main()