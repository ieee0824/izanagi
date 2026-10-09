"""One HTTP request split across distinct writers via fork/dup and SCM_RIGHTS."""
import array
import os
import socket

for mode in ["fork-dup", "scm-rights"]:
    stream = socket.create_connection(("127.0.0.1", 18080))
    body = b"DO_NOT_LOG_MIXED_WRITER_BODY"
    header = ("POST http://127.0.0.1:19090/DO_NOT_LOG_MIXED_WRITER_PATH HTTP/1.1\r\n"
              "Host: 127.0.0.1:19090\r\nConnection: close\r\nContent-Length: "
              + str(len(body)) + "\r\n\r\n").encode()
    stream.sendall(header)
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        parent.close()
        if mode == "scm-rights":
            stream.close()
            _, controls, _, _ = child.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
            fds = array.array("i")
            fds.frombytes(controls[0][2][:fds.itemsize])
            writer = socket.socket(fileno=fds[0])
        else:
            writer = socket.socket(fileno=os.dup(stream.fileno()))
        writer.sendall(body)
        writer.close()
        os._exit(0)
    child.close()
    if mode == "scm-rights":
        parent.sendmsg([b"f"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [stream.fileno()]))])
    _, status = os.waitpid(pid, 0)
    assert status == 0, status
    response = b""
    while True:
        chunk = stream.recv(4096)
        if not chunk:
            break
        response += chunk
    assert response.startswith(b"HTTP/1.1 200") and response.endswith(b"ok"), response
    stream.close()
    parent.close()
    print("VM_MIXED_WRITER_TRANSFER_OK", mode, flush=True)
