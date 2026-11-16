from fastapi import FastAPI
from poppy_docker.company import app as inner, clock
app=FastAPI()
@app.post('/_test/advance-clock')
async def advance():
    clock.advance(1800)
    return {'now':clock.now().isoformat()}
app.mount('/',inner)
