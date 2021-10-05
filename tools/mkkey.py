# -*- coding:utf-8 -*-

import os
import sys

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'kavcore'

sys.path.append(s)

import engine.kavcore.k2rsa

if __name__=='__main__':
    pu_fname='key.pkr'
    pr_fname='key.skr'

    if len(sys.argv)==3:
        pu_fname=sys.argv[1]
        pr_fname=sys.argv[2]
    elif len(sys.argv)!=1:
        print("Usage: mkkey.py [pu filename] [pr filename]")
        exit(0)

    engine.kavcore.k2rsa.create_key(pu_fname, pr_fname, True)  #공개키와 개인키 생성