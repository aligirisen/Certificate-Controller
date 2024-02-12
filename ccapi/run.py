'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
import threading, time
import time, configparser, os
from django.core.signals import request_started
from django.dispatch import receiver
from django.core.management import execute_from_command_line
import socket
from source.service import run_period

def django_thread():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ccapi.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(['manage.py', 'runserver', '--noreload'])
def period_thread(duration):
    while True:
        time.sleep(15)
        run_period()
        time.sleep(duration)

try:
    config_path = "/etc/certificate_controller/config.ini"

    config = configparser.ConfigParser()
    config.read(config_path)

    duration = int(config.get('TIME','duration'))
    duration = duration * 3600

    hostname = f"{(socket.gethostname()).upper()}$"

    django_thread = threading.Thread(target=django_thread)
    period_thread = threading.Thread(target=period_thread)

    django_thread.start()
    time.sleep(5)
    period_thread.start()


    django_thread.join()

except Exception as e:
    print("error:",e)
