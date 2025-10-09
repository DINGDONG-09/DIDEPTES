import time
import threading
import sys

class SimpleLoader:
    def __init__(self, message="Loading"):
        self.message = message
        self.is_running = False
        self.thread = None
        
    def start(self):
        self.is_running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self, result_message="Done"):
        self.is_running = False
        if self.thread:
            self.thread.join()
        
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        print(f"✅ {result_message}")
        sys.stdout.flush()
    
    def _animate(self):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        idx = 0
        while self.is_running:
            sys.stdout.write(f'\r{chars[idx % len(chars)]} {self.message}...')
            sys.stdout.flush()
            time.sleep(0.1)
            idx += 1