from fastapi import FastAPI

from .routes import ROUTER


app = FastAPI(title='BioVote API')
app.include_router(ROUTER)


@app.get('/health')
async def healthcheck():
  return {'status': 'ok'}
