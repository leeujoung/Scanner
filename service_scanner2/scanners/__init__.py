# scanners/__init__.py

import os
import importlib

# 현재 디렉토리의 모든 스크립트를 가져옵니다.
module_names = [f[:-3] for f in os.listdir(os.path.dirname(__file__)) if f.endswith('.py') and f != '__init__.py']

# 모든 모듈을 import 합니다.
for module_name in module_names:
    importlib.import_module(f'scanners.{module_name}')
