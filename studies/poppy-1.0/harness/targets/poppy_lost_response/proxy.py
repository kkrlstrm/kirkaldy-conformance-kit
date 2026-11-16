"""One-shot HTTP TCP proxy: capture upstream response, drop downstream socket."""
import asyncio, json
async def handle(reader, writer):
    upstream_w=None
    try:
        head=await reader.readuntil(b'\r\n\r\n')
        headers=head.decode('latin1').split('\r\n')
        length=next((int(x.split(':',1)[1]) for x in headers if x.lower().startswith('content-length:')),0)
        body=await reader.readexactly(length) if length else b''
        upstream_r,upstream_w=await asyncio.open_connection('company',8000)
        upstream_w.write(head+body); await upstream_w.drain()
        response_head=await upstream_r.readuntil(b'\r\n\r\n')
        lines=response_head.decode('latin1').split('\r\n')
        size=next((int(x.split(':',1)[1]) for x in lines if x.lower().startswith('content-length:')),None)
        if size is None:
            if not any(x.lower().startswith('transfer-encoding: chunked') for x in lines): raise RuntimeError('unknown response framing')
            parts=[]
            while True:
                chunk=int((await upstream_r.readline()).split(b';')[0].strip(),16)
                if not chunk:
                    await upstream_r.readuntil(b'\r\n'); break
                parts.append(await upstream_r.readexactly(chunk)); await upstream_r.readexactly(2)
            response=b''.join(parts)
        else:
            response=await upstream_r.readexactly(size)
        print('PROXY_RESPONSE '+json.dumps({'status_line':lines[0],'body':json.loads(response),'request_method_path':headers[0]},sort_keys=True),flush=True)
    except Exception as e: print('PROXY_ERROR '+repr(e),flush=True)
    finally:
        writer.close(); await writer.wait_closed()
        if upstream_w: upstream_w.close(); await upstream_w.wait_closed()
async def main():
    s=await asyncio.start_server(handle,'0.0.0.0',8000)
    async with s: await s.serve_forever()
asyncio.run(main())
