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


def run_period():
    try:
        config_path = "/etc/certificate_controller/config.ini"
        if os.path.exists(config_path):
            pass
        else:
            config_path = "config/config.ini"

        usernames = ['computer','ali','altay']
        

        for username in usernames:
            fetch_signedcer(username)
    except Exception as e:
        print(e)
