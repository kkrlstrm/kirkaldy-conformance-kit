from fastapi import FastAPI, Response
from poppy_docker.recorder import app as inner
app=FastAPI()
down=False
@app.post('/_test/down')
async def stop():
    global down
    down=True
    return {'down':True}
class Outage:
    async def __call__(self,scope,receive,send):
        if down and scope['type']=='http':
            await Response('recorder unavailable',status_code=503)(scope,receive,send)
        else:
            await inner(scope,receive,send)
app.mount('/',Outage())
