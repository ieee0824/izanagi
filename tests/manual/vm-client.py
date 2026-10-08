import socket,time,json,sys
routine = "--routine" in sys.argv
# Separate collector readiness / stdlib startup from the measured window.
time.sleep(31)
if not routine:
    with open('/workspace/dummy-credentials','rb') as f:f.read()
    try:open('/workspace/absent-credentials','rb')
    except FileNotFoundError:pass
s=socket.create_connection(('127.0.0.1',18080));pending=b''
timings=[]
for i in range(2):
    started=time.monotonic_ns()
    body=b'DO_NOT_LOG_BODY_CANARY'
    header=b'POST http://127.0.0.1:19090/DO_NOT_LOG_PATH_CANARY?canary=DO_NOT_LOG_QUERY_CANARY HTTP/1.1\r\nHost: 127.0.0.1:19090\r\nX-Canary: DO_NOT_LOG_HEADER_CANARY\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'
    s.sendall(header+body)
    while b'\r\n\r\n' not in pending:pending+=s.recv(4096)
    h,pending=pending.split(b'\r\n\r\n',1);n=int(next(l.split(b':',1)[1] for l in h.split(b'\r\n') if l.lower().startswith(b'content-length:')))
    while len(pending)<n:pending+=s.recv(4096)
    result,pending=pending[:n],pending[n:]
    assert h.startswith(b'HTTP/1.1 200') and result==b'ok',(h,result)
    timings.append(time.monotonic_ns()-started)
with open('/workspace/latency-'+('routine' if routine else 'access')+'.json','w') as f:json.dump(timings,f)
print('VM_KEEP_ALIVE_POST_OK')
s.close()
