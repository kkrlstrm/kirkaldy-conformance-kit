"""Study-owned SQLite CompanyStore. Shared POSIX filesystem required; not vendor code."""
import json, sqlite3, uuid
from datetime import datetime, timezone
from personal_agent_protocol.company.store import StoredRecord

class SQLiteStore:
    def __init__(self, path, now=None):
        self.path=path
        self.now=now or (lambda: datetime.now(timezone.utc))
        with sqlite3.connect(path,timeout=20) as c:
            c.execute('pragma journal_mode=wal')
            c.execute('create table if not exists records(kind text not null, key text not null, value text not null, version text not null, expires text, primary key(kind,key))')
    def transaction(self, action):
        with sqlite3.connect(self.path,timeout=20) as c:
            c.execute('begin immediate')
            c.execute('delete from records where expires is not null and expires <= ?', (self.now().isoformat(),))
            return action(c)
    @staticmethod
    def encode(value): return json.dumps(value,allow_nan=False,separators=(',',':'))
    @staticmethod
    def row(row):
        return None if row is None else StoredRecord(json.loads(row[0]),row[1],None if row[2] is None else datetime.fromisoformat(row[2]))
    @staticmethod
    def exp(value): return None if value is None else value.isoformat()
    async def get(self, kind, key):
        return self.transaction(lambda c:self.row(c.execute('select value,version,expires from records where kind=? and key=?',(kind,key)).fetchone()))
    async def put(self, kind, key, value, *, expires_at=None):
        self.transaction(lambda c:c.execute('insert or replace into records values (?,?,?,?,?)',(kind,key,self.encode(value),uuid.uuid4().hex,self.exp(expires_at))))
    async def create(self, kind, key, value, *, expires_at=None):
        def run(c):
            return c.execute('insert or ignore into records values (?,?,?,?,?)',(kind,key,self.encode(value),uuid.uuid4().hex,self.exp(expires_at))).rowcount==1
        return self.transaction(run)
    async def replace(self, kind, key, version, value, *, expires_at=None):
        def run(c):
            return c.execute('update records set value=?,version=?,expires=? where kind=? and key=? and version=?',(self.encode(value),uuid.uuid4().hex,self.exp(expires_at),kind,key,version)).rowcount==1
        return self.transaction(run)
    async def take(self,kind,key):
        def run(c):
            row=c.execute('select value from records where kind=? and key=?',(kind,key)).fetchone()
            if row is None: return None
            c.execute('delete from records where kind=? and key=?',(kind,key))
            return json.loads(row[0])
        return self.transaction(run)
    async def delete(self,kind,key):
        self.transaction(lambda c:c.execute('delete from records where kind=? and key=?',(kind,key)))
    async def records(self,kind):
        return self.transaction(lambda c:[self.row(row) for row in c.execute('select value,version,expires from records where kind=?',(kind,))])


class StaleSQLiteStore(SQLiteStore):
    """Known-bad host fixture; deliberately hides active/completed claims when enabled."""
    enabled=False
    async def get(self, kind, key):
        entry=await super().get(kind,key)
        if self.enabled and kind=='operation' and entry is not None and entry.value['status'] in ('performing','performed'):
            value=dict(entry.value)
            value['status']='open'
            value['outcome']=None
            return StoredRecord(value,entry.version,entry.expires_at)
        return entry


class CoordinatedSQLiteStore(SQLiteStore):
    """Instrument CAS at the host store boundary, never inside the SQLite transaction."""
    async def replace(self,kind,key,version,value,*,expires_at=None):
        import httpx, os
        if kind != 'operation' or value.get('status') != 'performing':
            return await super().replace(kind,key,version,value,expires_at=expires_at)
        marker={'operation_id':key,'version':version,'instance':os.environ['HOSTNAME'],'pid':os.getpid()}
        async with httpx.AsyncClient(trust_env=False,timeout=10) as h:
            r=await h.post('http://recorder:8002/claim-arrival',json=marker)
            r.raise_for_status()
            gate=r.json()
            if gate.get('armed') and not gate.get('released'):
                raise RuntimeError('claim synchronization incomplete')
            if gate.get('armed') and os.environ.get('RACE_MODE')=='bad':
                # Known-bad compare-and-set: overwrite despite a stale version.
                await super().put(kind,key,value,expires_at=expires_at)
                succeeded=True
            else:
                succeeded=await super().replace(kind,key,version,value,expires_at=expires_at)
            if gate.get('armed'):
                outcome=await h.post('http://recorder:8002/claim-outcome',json={**marker,'success':succeeded})
                outcome.raise_for_status()
            return succeeded
