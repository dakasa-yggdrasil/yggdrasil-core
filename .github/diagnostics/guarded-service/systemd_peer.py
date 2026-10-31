"""Root-owned throwaway systemd peer used only by Linux CI."""
import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.recv(1)
