from elasticsearch import Elasticsearch
import socket
import click
import requests
import json
from kazoo.client import KazooClient
import sys,re,os
import IPy # ip处理库
from colorama import Fore,Back,Style
from threading import Thread
from queue import Queue
from time import sleep,time
from random import choice
import argparse
from datetime import datetime
from html.parser import HTMLParser  
from bs4 import BeautifulSoup


burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
                 "Accept": "application/json, text/javascript, */*; q=0.01",
                 "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                 "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest",
                 "Connection": "close", "Referer": "https://www.butian.net/Loo/submit?cid=62715"}

def getV11Session(url):
    day1=str(datetime.now().day)
    hour1=str(datetime.now().hour)
    minute1=str(datetime.now().minute)
    try:
        checkUrl = "https://site.ip138.com/"+url+"/"
        req = requests.get(checkUrl,headers=burp0_headers,timeout=5)
        codetype=req.encoding#获取网页编码类型
        req.encoding='GBK'#更改网页编码类型
        html = req.text#将取出来的网页转换为text
        div_bf = BeautifulSoup(html,"html.parser")
        div = div_bf.find_all('div',class_='result result2')
        a_bf = BeautifulSoup(str(div[0:]),"html.parser")
        for a1 in a_bf.find_all(name='a')[0:]:
            if "/24" in a1.string:
                pass
            else:
                with open(day1+'-'+hour1+'：'+minute1+'汇总域名反查.txt', 'a', encoding='utf-8') as f:
                    f.writelines(a1.string)
                    f.write('\n')
                with open(url+"域名反查.txt", 'a', encoding='utf-8') as f:
                    f.writelines(a1.string)
                    f.write('\n')
    except:
        click.secho('请检查域名或者接口是否可用')

def create_queue(file_name):
    """
    创建数据队列
    argument: file_name -> 输入文件名
    return: data,total 数据队列,数据总数
    """
    total = 0
    data = Queue()
    for line in open(file_name):
        ip = line.strip()
        if ip:
            # 跳过空白的行
            data.put(ip)
            total += 1
    data.put(None)  # 结束标记
    return data, total
def start_jobs(data, num):
    """
    启动所有工作线程
    argument: data -> 数据队列 num -> 线程数
    """
    is_alive = [True]

    def job():
        """工作线程"""
        while is_alive[0]:
            try:
                ip = data.get()
                if ip == None:
                    # 遇到结束标记
                    break
                getV11Session(ip)# 验证漏洞
            except:
                is_alive[0] = False
        data.put(None)  # 结束标记

    jobs = [Thread(target=job) for i in range(num)]  # 创建多个线程
    for j in jobs:
        j.setDaemon(True)
        j.start()  # 启动线程

    for j in jobs:
        j.join()  # 等待线程退出
def main():
    if len(sys.argv) != 3:  # 判断输入长度是否合格
        print('Usage: python3 ip-find-url.py -h 10.10.10.10')
        print('Usage: python3 ip-find-url.py -r ip.txt')
        return
    a = str(sys.argv[1])  # 输入类型
    if a == '-h':
        ip = str(sys.argv[2]) # 获取ip地址
        #ipo = IPy.IP(ip,make_net=1)
        with open('one-ip.txt', 'w+') as f:
            f.write(str(ip) + "\n")
        f.close()
        num = 20  # 默认100线程
        data, total = create_queue("one-ip.txt")
        begin = time()
        start_jobs(data, num)
        # else:
        #     print("请输入正确的ip地址！")
        end = time()
        print('花费时间： %ss' % str(end - begin))
        print('已生成存域名反查.txt文件')
    elif a == '-r':
        file_name = str(sys.argv[2]) # 取文件名
        num = 20  # 默认100线程
        data, total = create_queue(file_name)  # 创建数据队列
        print('主机数量: %s' % total)
        begin = time()
        start_jobs(data,num)  # 启动工作线程
        end = time()
        print('花费时间： %ss' % str(end - begin))
        print('已生成存域名反查.txt文件')
    else:
        main()
if __name__ == '__main__':
    main()

