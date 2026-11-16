"""Independent loopback recorder; reuse the existing performing barrier."""
import os
import sqlite3
import time
from targets.poppy_race.recorder import app, path

with sqlite3.connect(path) as db:
    db.execute('create table if not exists marks (seq integer primary key, label text, ns integer)')

@app.post('/mark/{label}')
async def mark(label: str):
    stamp = time.monotonic_ns()
    with sqlite3.connect(path) as db:
        db.execute('insert into marks(label,ns) values (?,?)', (label, stamp))
    return {'label': label, 'ns': stamp}

@app.get('/marks')
async def marks():
    with sqlite3.connect(path) as db:
        return {'marks': [{'label': label, 'ns': ns} for label, ns in db.execute('select label,ns from marks order by seq')]}
