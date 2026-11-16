"""Test-only canonical-origin router: TCP between isolated containers, no TLS."""
import httpx
import os

class Routing(httpx.AsyncBaseTransport):
    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport(retries=0)
    async def handle_async_request(self, request):
        host = request.url.host
        target = {'manzanita.example': (os.environ.get('COMPANY_TARGET','company'), 8000), 'atlas.example': ('client', 8001)}.get(host)
        if not target:
            raise httpx.ConnectError(f'unknown origin {host}', request=request)
        original_url = request.url
        request.url = request.url.copy_with(scheme='http', host=target[0], port=target[1])
        try:
            response = await self.inner.handle_async_request(request)
        finally:
            request.url = original_url
        print(f'network {request.method} {host}{request.url.path} {response.status_code}', flush=True)
        return response
    async def aclose(self):
        await self.inner.aclose()

def client():
    return httpx.AsyncClient(transport=Routing(), timeout=15, trust_env=False)

async def resolve(host):
    if host not in ('manzanita.example', 'atlas.example'):
        raise ValueError('unknown origin')
    return ['93.184.216.34']
