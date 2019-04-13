from rest_framework import generics,status
from .models import MobileUser
#from .serializers import UserSerializer
from django.views.generic import ListView, DetailView 
from django.views.generic.edit import CreateView, UpdateView, DeleteView
import http.client
from urllib.parse import urlencode
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response
from django.http import HttpResponse
import json
from django.http import JsonResponse
from django.forms.models import model_to_dict
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import MobileUserSerializer

class MobileUserListView(generics.ListCreateAPIView):
    queryset = MobileUser.objects.all()
    serializer_class = MobileUserSerializer

class createMobileUser(generics.CreateAPIView):
    lookup_field='mobile'
    serializer_class=MobileUserSerializer
    #permission_classes = IsAuthenticated
    """ def get_queryset(self):
        return MobileUser.objects.all() """


# Create your views here.
@api_view(['POST'])
@permission_classes((AllowAny,))
def generateOTP(request):
    mobile=request.data.get("mobile")
    conn = http.client.HTTPConnection("control.msg91.com")
    payload = {'authkey':"271650AhgEeZi4lz5caca5e1",'message':"your otp is ##OTP##",'sender':"ABCDEF",'mobile':mobile}
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'x-csrf-token': "wWjeFkMcbopci1TK2cibZ2hczI",
    'cache-control': "no-cache",
    'postman-token': "23c09c76-3b030-eea1-e16ffd48e9"
    }
    conn.request("POST", "/api/sendotp.php?otp_length=&authkey=&message=&sender=&mobile=&otp=&email=&otp_expiry=&template=", urlencode(payload),headers)
    
    res = conn.getresponse()
    data = res.read().decode("utf-8")
    json_data_response = json.loads(data)
    return JsonResponse(json_data_response)

@api_view(['POST'])
@permission_classes((AllowAny,))
def verifyOTP(request):
    mobile=request.data.get("mobile")
    otp=request.data.get("otp")
    print(mobile)
    conn = http.client.HTTPSConnection("control.msg91.com")
    headers = { 'content-type': "application/x-www-form-urlencoded" }
    payload={
        'authkey':"271650AhgEeZi4lz5caca5e1",
        'mobile': mobile,
        'otp': otp
    }
    conn.request("POST", "/api/verifyRequestOTP.php?authkey=&mobile=&otp=", urlencode(payload),headers)
    res = conn.getresponse()
    data = res.read().decode("utf-8")
    json_data_response = json.loads(data)
    print(json_data_response)
    if json_data_response['type'] == 'success':
        is_registered = MobileUser.objects.filter(mobile=mobile).exists()
        json_data_response['is_registered'] = is_registered
        if is_registered:
            user_data_json = model_to_dict( MobileUser.objects.get(mobile=mobile) )
            json_data_response['user_data'] = user_data_json
            return JsonResponse(json_data_response)
        else:
            pass
            serializer = MobileUserSerializer(data={'mobile': '8459886765', 'otp': '1234'})
            if serializer.is_valid():
                print(serializer.validated_data)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        json_data_response['user_data'] = "OTP verified,Please register"
        return JsonResponse(json_data_response)
    else:
        pass
        #Should return Error resonse
    return JsonResponse(json_data_response)