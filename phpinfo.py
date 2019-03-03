#-*- coding:utf-8 -*-
import re
import requests
import sys
from bs4 import BeautifulSoup, element
from tabulate import tabulate
import wcwidth

#将重要信息取出，转化为dict
def info_to_dict(html):
    phpinfo_dict = {}
    #基本信息，固定为第二个table
    phpinfo_dict["Baseinfo"] = {}
    base_info_table = html.select("body > div.center > table:nth-child(2)")[0]
    for tr in base_info_table.find_all("tr"):
        key   = tr.select("td.e")[0].string.strip()
        value = tr.select("td.v")[0].string.strip()
        phpinfo_dict["Baseinfo"][key] = value

    for h2 in html.find_all("h2"):
        module_name = h2.string.strip()
        phpinfo_dict[module_name] = {}
        #每一个配置模块是从h2标题开始的，向下寻找所有的table标签
        #有一个特殊情况PHP Credits，它在h1标签中，其内容是php及其sapi、module等的作者，对脚本功能没有意义，所以不解析
        for sibling in h2.next_siblings:
            #使用next_siblings会匹配到许多\n \t等，需特殊处理，官方文档明确提到
            if sibling.name != "table" and type(sibling) != element.NavigableString:
                break
            if sibling.name == "table":
                for tr in sibling.find_all("tr"):
                    key_elements = tr.select("td.e")
                    if len(key_elements) == 0:
                        continue
                    key = key_elements[0].string.strip()

                    value_elements = tr.select("td.v")
                    if len(value_elements) == 0:
                        value = ''
                    elif len(value_elements) == 2:
                        # 有些配置的value分为Local Value和Master Value
                        # local value是当前目录的设置，会受.htaccess、.user.ini、代码中ini_set()等的影响
                        # master value是php.ini中的值
                        value = [value_elements[0].string.strip(), value_elements[1].string.strip()]
                    else:
                        value = "no value" if value_elements[0].string == None else value_elements[0].string.strip()
                    phpinfo_dict[module_name][key] = value
    
    #windos _SERVER["xx"]
    #linux $_SERVER['xx']
    #消除这种差异
    php_var_dict = {}
    if list(phpinfo_dict["PHP Variables"].keys())[0][0] == "_":
        for key in phpinfo_dict["PHP Variables"].keys():
            new_key = "$" + key.replace('"', "'")
            php_var_dict[new_key] = phpinfo_dict["PHP Variables"][key]
        phpinfo_dict["PHP Variables"] = php_var_dict
    return phpinfo_dict

#获取关键信息
def get_important_info(phpinfo_dict):
    result = []
    #web目录
    result.append(["Web Path", phpinfo_dict["PHP Variables"]["$_SERVER['SCRIPT_FILENAME']"]])
    #真实ip
    server_ip = phpinfo_dict["PHP Variables"]["$_SERVER['LOCAL_ADDR']"] if "$_SERVER['LOCAL_ADDR']" in phpinfo_dict["PHP Variables"] else phpinfo_dict["PHP Variables"]["$_SERVER['SERVER_ADDR']"]
    result.append(["Server IP", server_ip])
    #中间件
    result.append(["Software", phpinfo_dict["PHP Variables"]["$_SERVER['SERVER_SOFTWARE']"]])
    #php版本
    phpversion = phpinfo_dict["Core"]["PHP Version"]
    result.append(["PHP Version", phpversion])
    #系统信息
    result.append(["System", phpinfo_dict["Baseinfo"]["System"]])
    #SAPI
    result.append(["Server API", phpinfo_dict["Baseinfo"]["Server API"]])
    #Registered PHP Streams
    result.append(["Registered PHP Streams", phpinfo_dict["Baseinfo"]["Registered PHP Streams"]])
    #allow_url_include
    result.append(["Allow Url Include", ", ".join(phpinfo_dict["Core"]["allow_url_include"])])
    #asp_tags
    #php7之后已移除
    if "asp_tags" in phpinfo_dict["Core"]:
        result.append(["Asp Tags", ", ".join(phpinfo_dict["Core"]["asp_tags"])])
    #short_open_tag
    result.append(["Short Open Tag", ", ".join(phpinfo_dict["Core"]["short_open_tag"])])
    #enable_dl
    result.append(["Enable Dl", ", ".join(phpinfo_dict["Core"]["enable_dl"])])
    #open_basedir
    result.append(["Open Basedir", ", ".join(phpinfo_dict["Core"]["open_basedir"])])
    #session
    ser_handler = ",".join(phpinfo_dict["session"]["session.serialize_handler"])
    upload_progress_enabled = ",".join(phpinfo_dict["session"]["session.upload_progress.enabled"])
    upload_progress_cleanup = ",".join(phpinfo_dict["session"]["session.upload_progress.cleanup"])
    upload_progress_name = ",".join(phpinfo_dict["session"]["session.upload_progress.name"])
    session_info = "session.serialize_handler:       %s\nsession.upload_progress.enabled: %s\nsession.upload_progress.cleanup: %s\nsession.upload_progress.name:    %s" % (ser_handler, upload_progress_enabled, upload_progress_cleanup, upload_progress_name)
    result.append(["Session", session_info])
    #curl
    #if  "curl" in phpinfo_dict:
        #result.append(["Curl Protocols", phpinfo_dict["curl"]["Protocols"].replace(" ", "")])
    #libxml
    if "libxml" in phpinfo_dict:
        result.append(["Libxml Version", phpinfo_dict["libxml"]["libXML Compiled Version"]])
    #disable function
    disable_func = phpinfo_dict["Core"]["disable_functions"][0]
    result.append(["Disable Function", disable_func.replace(",", "\n")])
    #extentions
    extentions = ["imagick", "memcache", "redis", "xdebug", "opcache", "imap"]
    exist_ext = []
    for ext in extentions:
        if ext in phpinfo_dict:
            exist_ext.append(ext)
    intresting_exts = "No Intrestring Ext" if len(exist_ext) == 0 else ", ".join(exist_ext)
    result.append(["Extentions", intresting_exts])

    return tabulate(result, tablefmt="psql")

#解析获取到的信息，如bypass_disable_function、php版本特性等
def get_parsed_info(phpinfo_dict):
    result = []
    #php version
    suggestion = get_version_feature(phpinfo_dict["Core"]["PHP Version"])
    if suggestion:
        result.append([suggestion])
    #sapi
    sapi = phpinfo_dict["Baseinfo"]["Server API"]
    if "FPM" in sapi:
        result.append(["SAPI为fpm，可能存在未授权访问漏洞"])
    #phar
    if "phar" in phpinfo_dict["Baseinfo"]["Registered PHP Streams"]:
        result.append(["支持phar协议，可扩展反序列化攻击面"])
    #ssrf curl php_wrapper
    protocols = ["gopher", "dict"]
    available_protocols = []
    if "curl" in phpinfo_dict:
        for protocol in protocols:
            if protocol in phpinfo_dict["curl"]["Protocols"]:
                available_protocols.append(protocol)
        result.append(["libcurl支持%s协议" % (", ".join(available_protocols))])
    #libxml版本
    if "libxml" in phpinfo_dict and phpinfo_dict["libxml"]["libXML Compiled Version"] < "2.9":
        result.append(["libxml版本 < 2.9 xxe可利用"])
    #session upload progress
    if phpinfo_dict["session"]["session.upload_progress.enabled"][0] == "On":
        suggestion = "可利用session.upload_progress上传临时文件然后包含"
        if phpinfo_dict["session"]["session.upload_progress.cleanup"][0] == "On":
            suggestion += "\n临时文件会立刻删除，需用条件竞争getshell"
        result.append([suggestion])
    #session ser handler
    if phpinfo_dict["session"]["session.serialize_handler"][0] != phpinfo_dict["session"]["session.serialize_handler"][1]:
        result.append(["ser handler不一致，存在反序列化风险"])
    #imagick
    if "imagick" in phpinfo_dict:
        result.append(["可利用imagick相关漏洞"])
    #xdebug
    if "xdebug" in phpinfo_dict and phpinfo_dict["xdebug"]["xdebug.remote_connect_back"][0] == "On" and phpinfo_dict["xdebug"]["xdebug.remote_enable"][0] == "On":
        result.append(["存在xdebug rce https://github.com/vulhub/vulhub/tree/master/php/xdebug-rce\nxdebug idekey: " + phpinfo_dict["xdebug"]["xdebug.idekey"][0]])
    #opcache
    if "opcache" in phpinfo_dict:
        result.append(["可上传opcache覆盖源文件"])
    #imap
    if "imap" in phpinfo_dict:
        result.append(["可能存在imap rce https://github.com/vulhub/vulhub/blob/master/php/CVE-2018-19518/README.md"])
    #disable function
    if phpinfo_dict["Core"]["disable_functions"][0] != "no value":
        result.append([bypass_disable_function(phpinfo_dict["Core"]["disable_functions"][0], phpinfo_dict)])
    return tabulate(result, tablefmt="grid")

#根据版本获取版本特性
def get_version_feature(version):
    suggestion = ""
    if "7.2" in version:
        suggestion = "php 7.2: assert从函数变为语法结构，无法动态调用; 移除create_function"
    if "7.0" in version:
        suggestion = "php 7.0: 移除dl; 不再支持asp_tag、<script language=\"php\">"
    return suggestion

#如果存在disable_function，寻找可能的bypass
def bypass_disable_function(disable_func, phpinfo_dict):
    disable_func = disable_func.split(",")
    suggestion = ""
    bypass_func = []
    if "dl" not in disable_func and phpinfo_dict["Core"]["enable_dl"] == "On":
        bypass_func.append("dl")
    if "pcntl_exec" not in disable_func and "--enable-pcntl" in phpinfo_dict["Baseinfo"]["Configure Command"]:
        bypass_func.append("pcntl_exec")
    if "Linux" in phpinfo_dict["Baseinfo"]["System"] and "putenv" not in disable_func and "mail" not in disable_func:
        suggestion += "使用LD_PRELOAD https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD\n"
    if "imap" in phpinfo_dict:
        suggestion += "使用imap https://github.com/vulhub/vulhub/blob/master/php/CVE-2018-19518/README.md\n"
    if "imagemagick" in phpinfo_dict:
        suggestion += "使用 ImageMagick\n"
    common_funcs = ['exec', 'system', 'passthru', 'popen', 'proc_open', 'shell_exec']
    suggestion += "disable function bypass合集 https://github.com/l3m0n/Bypass_Disable_functions_Shell"
    return suggestion

def parse_phpinfo(url):
    r = requests.get(url)
    #print(r.text)
    html = BeautifulSoup(r.text, "lxml")
    phpinfo_dict = info_to_dict(html)
    #pprint.pprint(phpinfo_dict)
    print(get_important_info(phpinfo_dict))
    print(get_parsed_info(phpinfo_dict))

if __name__ == "__main__":
    url = sys.argv[1]
    parse_phpinfo(url)
