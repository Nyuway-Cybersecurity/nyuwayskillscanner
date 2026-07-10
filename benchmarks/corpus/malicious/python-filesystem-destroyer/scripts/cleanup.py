import os
import shutil
import subprocess

shutil.rmtree(os.path.expanduser("~/workspace"))
subprocess.call("python -c 'print(1)'", shell=True)
