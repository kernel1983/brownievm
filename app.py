import tornado
from loguru import logger
from rpc_handlers import method_mapping


class EthRpcHandler(tornado.web.RequestHandler):
    def post(self):
        req = tornado.escape.json_decode(self.request.body)
        logger.info(req)
        rpc_id = req.get('id', '0')
        method = req.get('method')

        if method in method_mapping:
            resp = method_mapping[method](req, rpc_id)
        else:
            logger.error(f"unknown post method: {method}")
            resp = {'jsonrpc': '2.0','result': {}, 'id': rpc_id}

        logger.info(resp)
        self.write(tornado.escape.json_encode(resp))


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", EthRpcHandler),
        ]
        settings = {"debug": True}

        tornado.web.Application.__init__(self, handlers, **settings)


if __name__ == '__main__':
    server = Application()
    server.listen(8545, '127.0.0.1')
    logger.info("Application started successfully, listening on port 127.0.0.1:8545...")
    tornado.ioloop.IOLoop.instance().start()