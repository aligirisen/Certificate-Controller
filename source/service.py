'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
import time, configparser, os
from fetch_signedcer import fetch_signedcer
import psutil, socket

def get_users(usernames):
    for user in psutil.users():
        usernames.append(user.name)
    return usernames

config_path = "/etc/certificate_controller/config.ini"
if os.path.exists(config_path):
    pass
else:
    config_path = "config/config.ini"


config = configparser.ConfigParser()
config.read(config_path)

user_counter = len(psutil.users())

duration = int(config.get('TIME','duration'))
duration = duration * 3600


usernames = []
hostname = f"{(socket.gethostname()).upper()}$"
usernames = get_users(usernames)

while True:
    if user_counter != len(psutil.users()):
        usernames = get_users()
    for username in usernames:
        fetch_signedcer(username)
    time.sleep(duration)
