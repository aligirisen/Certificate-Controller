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


def run_period(usernames):
    for username in usernames:
        try:
            fetch_signedcer(str(username),0)
        except Exception as e:
            print(e)
