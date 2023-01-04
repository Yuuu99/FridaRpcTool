from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import frida
from urllib.parse import unquote_to_bytes

def startRpcServer():
    jsCode = """
        function hook(item_mode, item_data){
            var result;
            var data;
            Java.perform(function(){
                var p = Java.use("加密算法所在类名");

                if(item_mode == 0){
                    // 加密
                    data = p.encrypt(item_data);
                } else {
                    // 解密
                    data = p.decrypt(item_data);
                }
            });
            return data;
        }
        rpc.exports = {
            rpc: hook
        };
    """

    # 调用 Frida
    process = frida.get_usb_device().attach(app pid 数值)
    script = process.create_script(jsCode)
    print('[*] FridaRpcTool Running')
    script.load()

    app = FastAPI()

    class Item(BaseModel):
        # 模式
        # 0 加密 1 解密
        item_mode: str = None
        # 数据
        item_data: str = None

    @app.post("/post")
    async def getEchoApi(postData: Item):
        data = script.exports.rpc(postData.item_mode, postData.item_data)

        # URL 解码
        if postData.item_mode == "1":
            data = unquote_to_bytes(data).decode()

        return {"item_mode": postData.item_mode, "item_data": data}

    uvicorn.run(app, port=8088)

if __name__ == '__main__':
    startRpcServer()