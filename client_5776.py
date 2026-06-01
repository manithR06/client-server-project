import socket

HOST = "127.0.0.1"
PORT = 50776

def send_command(sock, cmd, arg1="", arg2=""):
    payload = " ".join([x for x in [cmd, arg1, arg2] if x])

    message = f"LEN:{len(payload)}\n{payload}"
    sock.sendall(message.encode())

    response = sock.recv(4096).decode()
    return response.strip()

def main():
    token = ""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((HOST, PORT))
            print(f"[+] Connected to server on port {PORT}")

            while True:
                user_input = input("\n> ").strip()
                if not user_input:
                    continue

                parts = user_input.split()
                cmd = parts[0].upper()

                if cmd == "EXIT":
                    print("[*] Closing connection...")
                    break

                elif cmd == "REGISTER":
                    if len(parts) != 3:
                        print("Usage: REGISTER <username> <password>")
                        continue

                    resp = send_command(client, "REGISTER", parts[1], parts[2])
                    print("[SERVER]", resp)

                elif cmd == "LOGIN":
                    if len(parts) != 3:
                        print("Usage: LOGIN <username> <password>")
                        continue

                    resp = send_command(client, "LOGIN", parts[1], parts[2])
                    print("[SERVER]", resp)

                    if resp.startswith("OK"):
                        token = resp.split()[-1]
                        print(f"[+] Token saved: {token}")

                elif cmd == "LOGOUT":
                    if not token:
                        print("[!] You are not logged in")
                        continue

                    resp = send_command(client, "LOGOUT", token)
                    print("[SERVER]", resp)

                    if resp.startswith("OK"):
                        token = ""
                        print("[*] Logged out successfully")

                else:
                    if not token:
                        print("[!] Access Denied. Please LOGIN first.")
                        continue

                    resp = send_command(client, cmd, token)
                    print("[SERVER]", resp)

        except ConnectionRefusedError:
            print("[!] Cannot connect to server. Run server first.")
        except Exception as e:
            print("[!] Error:", e)


if __name__ == "__main__":
    main()
