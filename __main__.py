from asyncio import run
from os import getenv

from dotenv import load_dotenv
from uvicorn import Config, Server

load_dotenv()

async def main():
    config = Config('app:fastapi', port=getenv('PORT', 5000), log_level="info", root_path='/api', uds=getenv('UNIX_SOCKET', None))
    server = Server(config)
    await server.serve()

if __name__ == '__main__':
    run(main())