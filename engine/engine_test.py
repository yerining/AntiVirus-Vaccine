# -*- coding:utf-8 -*-

import os
import sys

import kavcore.k2engine

# listvirus의 콜백함수
def listvirus_callback(plugin_name, vnames) :
    for vname in vnames:
        print('%-50s [%s.kmd]' %(vname, plugin_name))

k2=kavcore.k2engine.Engine(debug=True)

if k2.set_plugins('plugins'):   #플러그인 엔진 경로 정의
    kav=k2.create_instance()    #백신 c엔진 인스턴스 생성
    if kav:
        print("[* Success: create instance]")

        ret = kav.init() # 플러그엔진 초기화
        info = kav.getinfo()

        vlist = kav.listvirus(listvirus_callback) # 플러그인의 바이러스 목록을 출력한다.

        print('[*] Used Callback    : %d' % len(vlist))

        vlist = kav.listvirus() # 플러그인의 바이러스 목록을 얻는다.
        print('[*] Not Used Callback : %d' % len(vlist))

        ret, vname, mid, eid = kav.scan('eicar.txt')

        kav.uninit() # 플러그인엔진 종료