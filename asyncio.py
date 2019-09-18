import asyncio
import datetime

async def main():
    loop = asyncio.get_running_roop()
    end_time = loop.time()+5.0
    while True:
        print(date.datetime.now())
        if (loop.time+1) >= ent_time:
            break
        await asyncio.sleep(1)

