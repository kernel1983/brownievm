import tornado.web
from rpc_handlers import method_registry, create_response

class EthRpcHandler(tornado.web.RequestHandler):
    def initialize(self, chain, state, miner):
        """
        初始化方法，用于接收依赖
        """
        self.chain = chain
        self.state = state
        self.miner = miner

    def post(self):
        req = tornado.escape.json_decode(self.request.body)
        rpc_id = req.get('id', '0')
        method_name = req.get('method', '').lower()
        params = req.get('params', [])

        # 自动查找方法
        if method_name in method_registry:
            response = method_registry[method_name](self, req, params, rpc_id)  # 需要适配参数
        else:
            response = create_response(
                error={'code': -32601, 'message': 'Method not found'},
                rpc_id=rpc_id
            )

        self.write(tornado.escape.json_encode(response))

    def set_default_headers(self):
        """设置 CORS 头"""
        self.add_header('Access-Control-Allow-Origin', '*')
        self.add_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With')
        self.add_header('Access-Control-Allow-Methods', 'POST, OPTIONS')

    def options(self):
        """处理预检请求"""
        self.set_status(204)  # No Content
        self.finish()