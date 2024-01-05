'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
import time, configparser
from fetch_signedcer import fetch_signedcer


config_path = "/etc/certificate_controller/config.ini"
if os.path.exists(config_path):
    pass
else:
    config_path = "config/config.ini"


config = configparser.ConfigParser()
config.read(config_path)

duration = int(config.get('TIME','duration'))

while True:
    fetch_signedcer()
    time.sleep(duration)

