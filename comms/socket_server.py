import socket
import json
from detection_engine.core.detector import analyze_packet

HOST = "127.0.0.1"
PORT = 9999

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)

    print(f"[+] Listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")

    buffer = ""

    while True:
        data = conn.recv(1024)

        if not data:
            break

        buffer += data.decode()

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)

            try:
                packet = json.loads(line)
                print(f"[DEBUG] Packet: {packet}")
                analyze_packet(packet)
            except Exception as e:
                print(f"[ERROR] {e}")

if __name__ == "__main__":
    start_server()