import asyncio

# A wrapper class for asyncio.Future so we can use errorBacks
# (also so I don't have to change a hundred lines of code...)
class Deferred(asyncio.Future):
    def __init__(self):
        self.f = asyncio.Future()

    """def __cb(self, fut, func):
        # might want to remove .done() check to better catch errors
        # (.result() throws an error if not done)
        if fut.done() and fut.result():
            return func(fut.result())
        return None # should I return an exception instead?"""

    def addCallback(self, func):
        return self.add_done_callback(func)

    def callback(self, res):
        return self.set_result(res)

    """def __eb(self, fut, func):
        # might want to remove .done() check to better catch errors
        # (.exception() throws an error if not done)
        if fut.done() and fut.exception():
            return func(fut.exception())
        return None # should I return an exception instead?"""

    def addErrback(self, func):
        return self.add_done_callback(func)

    def errback(self, exc):
        return self.set_exception(exc)
