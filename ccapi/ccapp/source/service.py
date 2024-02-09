'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
import time, configparser, os, re
from django.core.signals import request_started
from django.dispatch import receiver
from .fetch_signedcer import fetch_signedcer
import psutil, socket



#lokal kullanıcılar
#def get_all_users(usernames):
  #  for user in psutil.users():
 #       usernames.append(user.name)
#    return usernames


def login(username):
    try:
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
        #usernames = get_users(usernames)

        #while True:
        fetch_signedcer(username)
            #time.sleep(duration)
    except Exception as e:
        print(e)
