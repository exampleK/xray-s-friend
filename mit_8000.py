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
KEY='des的key'
# 
endata_3 = ''
endata_1 = ''
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
    str1 = str1+"des的key"
    # print(str1)
    i.update(bytes(str1, encoding = "utf8"))
    # print(i.hexdigest())
    return i.hexdigest()
def request(flow: mitmproxy.http.HTTPFlow):
    request = flow.request
    info = ctx.log.info
    # 判断post参数
    ## 获得post参数
    # info(str(request.text))
    '''
    if body中有des参数：
        分割处理
    else：
        加密处理，加工三段
        发送其他不转发的proxy
    '''
    global endata_3
    encryptdata = flow.request.get_text()
    print('1'+'*'*30)
    print(encryptdata)
    print('1'+'*'*30)
    import json
    try:
        strdata_all = json.loads(encryptdata)
    except:
        strdata_all = ''
    else:
        pass
    # strdata_all = json.loads(encryptdata)
    if "encryptData" in strdata_all:
        print('2'+"*"*30)
        strdata_2 = strdata_all["encryptData"]
        # print(strdata_2)
        en_strdata_all = strdata_2.split("")
        # print(en_strdata_all)   
        # print(en_strdata_all[0])
        print(en_strdata_all[1])
        # print(en_strdata_all[2])
        print(des_descrypt(en_strdata_all[1]))
        # 存储第三段字符串
        endata_3 = en_strdata_all[2]
        # 修改发送到xray的报文
        flow.request.set_text(des_descrypt(en_strdata_all[1]))
        '''
        {"tc":"szmbank","tcard":"6"}
        '''
        print('2'+"*"*30)
        #发送到上游xray处
    else:
        # 被xray处理的原始字符串--》即将加密还原
        print("!"*30)
        if strdata_all == '':
            pass
        else:
            # endata_3 = '4a8fd18243825924e664e001b357958a764f59f47412911be36f687d0271f5e335779c6042b8f108ca4246e23cedb74995dbff9d48440581945e8c670072771d60278ee3df4290bf8e69c6007237f0b4792c85ad4dea61abe2b6d23117a5c05493250bffe29330455e8e06a40ba69c209f23db4d96db0d49feb207f1c8910d0c'
            # print(strdata_all)
            print("[payload]"+str(strdata_all))
            strdata_1 = des_encrypt(str(strdata_all))
            strdata_0 = encode_md5(str(strdata_all))
            strdata_all = strdata_0+'\u001d'+strdata_1+'\u001d'+endata_3
            # print(strdata_all)
            data_json = {"encryptData":strdata_all}
            print(data_json)
            flow.request.set_text(str(data_json))
        # 发送到8001代理正常出去
        print("即将发送。。。。")
        proxy =("localhost", 8001)
        flow.live.change_upstream_proxy_server(proxy)
        print("发送成功。。。。")
def response(flow):
    # 获取响应对象
    response = flow.response
    print("response-->"+endata_1)
    info = ctx.log.info
    info(str(response.text))
    '''
    # 实例化输出类
    info = ctx.log.info
    # 打印响应码
    info(str(response.status_code))
    # 打印所有头部
    info(str(response.headers))
    # 打印cookie头部
    info(str(response.cookies))
    # 打印响应报文内容
    info(str(response.text))
    '''