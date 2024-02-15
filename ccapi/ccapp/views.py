"""
Author: Ali Riza Girisen
Date: 06/02/2024
"""
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .source.service import login
from ccapp.models import Username
import json, threading, socket


@csrf_exempt
def login_api(request):
    def add_user(username):
        if not Username.objects.filter(name=username).exists():
            user = Username(name=username)
            user.save()

    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            username = data.get('username',{})
            login(username)
            hostname = f"{(socket.gethostname()).upper()}$"
            add_user(username)
            add_user(hostname)
            
            return JsonResponse({'success':'True'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse ({'error': 'Invalid JSON format in the request body'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'})
