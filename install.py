#!/usr/bin/env python3
import os
import sys
clean_dist = os.system('rm -rf dist')
if clean_dist == 0:
    print("清除历史包数据")
exit_code = os.system('python3 setup.py sdist bdist_wheel')
upload_code = 0
if exit_code == 0:
    isUpload = input('打包成功...是否上传(y/n): ')
    if isUpload == 'y' or isUpload == 'Y' or isUpload == '':
        plat_from = input(
        '''
选择上传平台: 
1. pypi
2. testpypi
3. 其他退出
等待输入:''')
        print(plat_from)
        if plat_from == '1' or plat_from == '':
            upload_code = os.system('python3 -m twine upload -r pypi dist/*  --verbose')
        elif plat_from == '2':
            upload_code = os.system('python3 -m twine upload -r testpypi dist/*  --verbose')
        else:
            print('退出!!!!')
            exit()
        if upload_code == 0:
            print('上传成功!!!')
    else:
        exit()
