FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /work
COPY docs/studies/poppy/evidence/2026-11-15-amo-v1/dependencies.lock /tmp/dependencies.lock
COPY docs/studies/poppy/evidence/2026-11-15-amo-v1/build.lock /tmp/build.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/dependencies.lock -r /tmp/build.lock
RUN python -c "import json,urllib.request,hashlib,pathlib; j=json.load(urllib.request.urlopen('https://pypi.org/pypi/personal-agent-protocol/0.35.0/json')); u=next(x['url'] for x in j['urls'] if x['packagetype']=='sdist'); b=urllib.request.urlopen(u).read(); assert hashlib.sha256(b).hexdigest()=='9dd19ae05fba005deca4d38c9e33fcdb865540c30fd77557cd49910bbf7f50a3'; pathlib.Path('/tmp/personal_agent_protocol-0.35.0.tar.gz').write_bytes(b)" && pip install --no-cache-dir --no-build-isolation --no-deps /tmp/personal_agent_protocol-0.35.0.tar.gz
COPY targets/poppy_race /work/poppy_docker
ENV PYTHONPATH=/work PYTHONUNBUFFERED=1
