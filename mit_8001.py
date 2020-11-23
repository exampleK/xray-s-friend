from json import encoder
from mitmproxy import ctx
import mitmproxy
'''
# des加解密

'''
from pyDes import des, CBC, PAD_PKCS5 ,ECB
import binascii
# 所有发出的请求数据包都会被这个方法所处理
# 所谓的处理，我们这里只是打印一下一些项；当然可以修改这些项的值直接给这些项赋值即可
'''
md5加密
'''
import hashlib

'''
# des加解密

'''
# 秘钥
KEY=''
def des_encrypt(s):
    """
    DES 加密
    :param s: 原始字符串
    :return: 加密后字符串，16进制
    """
    secret_key = KEY
    iv = secret_key
    k = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
    en = k.encrypt(s, padmode=PAD_PKCS5)
    # print(str(binascii.b2a_hex(en),encoding="utf8"))
    return str(binascii.b2a_hex(en),encoding="utf8")
def des_descrypt(s):
    """
    DES 解密
    :param s: 加密后的字符串，16进制
    :return:  解密后的字符串
    """
    secret_key = KEY
    iv = secret_key
    k = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
    de = k.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
    # print(str(de,encoding="utf8"))
    return str(de,encoding="utf8")
def encode_md5(str1):
    i = hashlib.md5() # 计算的参数必须是 bytes 类型
    str1 = str1+""
    # print(str1)
    i.update(bytes(str1, encoding = "utf8"))
    # print(i.hexdigest())
    return i.hexdigest()

# 
endata_3 = ''

def request(flow: mitmproxy.http.HTTPFlow):
    # 获取请求对象
    request = flow.request
    # 实例化输出类
    info = ctx.log.info
    '''
    # 打印请求的url
    info(request.url)
    # 打印请求方法
    info(request.method)
    # 打印host头
    info(request.host)
    # 打印请求端口
    info(str(request.port))
    # 打印所有请求头部
    info(str(request.headers))
    # 打印cookie头
    info(str(request.cookies))
    '''
    print("》------------request------------------")
    print(flow.request.get_text())
    print("--------------request----------------《")
# 所有服务器响应的数据包都会被这个方法处理
# 所谓的处理，我们这里只是打印一下一些项
def response(flow):
    # 获取响应对象
    response = flow.response
    # 实例化输出类
    info = ctx.log.info
    print("》-----------response-----------------")
    # 打印响应码
    # info(str(response.status_code))
    '''
    # 打印所有头部
    info(str(response.headers))
    # 打印cookie头部
    info(str(response.cookies))
    '''
    # 打印响应报文内容
    print(str(response.text))
    # info(str(response.text))
    print("-------------response-----------------《")
