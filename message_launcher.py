import tkinter as tk
import sys
import os

# Add the current directory to the path to ensure imports work
sys.path.append(os.path.abspath('.'))

def launch_client():
    try:
        from core.messaging.messaging import start_messaging_module
        root = tk.Tk()
        start_messaging_module(root)
        root.mainloop()
    except Exception as e:
        print(f"Error starting client: {e}")
        import traceback
        traceback.print_exc()

def launch_server():
    try:
        from core.messaging.messaging import run_server
        run_server()
        print("Server started. Press Ctrl+C to stop.")
        while True:
            pass  # Keep running until keyboard interrupt
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Messaging Launcher")
    root.geometry("300x200")
    
    # Create buttons for launching messaging client or server
    frame = tk.Frame(root, padx=20, pady=20)
    frame.pack(expand=True)
    
    tk.Label(frame, text="MyLanManager Messaging", font=("Arial", 14, "bold")).pack(pady=10)
    
    client_btn = tk.Button(frame, text="Start Messaging Client", 
                          command=lambda: [root.destroy(), launch_client()])
    client_btn.pack(fill="x", pady=5)
    
    server_btn = tk.Button(frame, text="Start Messaging Server", 
                          command=lambda: [root.destroy(), launch_server()])
    server_btn.pack(fill="x", pady=5)
    
    root.mainloop()