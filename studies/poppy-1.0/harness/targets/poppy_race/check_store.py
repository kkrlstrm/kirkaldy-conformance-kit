import asyncio, pathlib, tempfile
from personal_agent_protocol.company.testing import check_store
from poppy_docker.sqlite_store import SQLiteStore

async def main():
    with tempfile.TemporaryDirectory() as directory:
        sequence=iter(range(100))
        await check_store(lambda: SQLiteStore(str(pathlib.Path(directory)/f'{next(sequence)}.db')))
    print('HOST_STORE_CHECK pass', flush=True)
asyncio.run(main())
