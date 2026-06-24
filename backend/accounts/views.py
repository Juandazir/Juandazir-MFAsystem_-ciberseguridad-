import pyotp
from rest_framework import status, views, response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import CustomUser
from .serializers import UserSerializer, LoginSerializer

class RegisterView(views.APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = CustomUser.objects.create_user(**request.data)
            return response.Response(serializer.data, status=status.HTTP_201_CREATED)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(email=serializer.data['email'], password=serializer.data['password'])
        
        if user:
            if user.is_locked:
                if user.lockout_until and user.lockout_until > timezone.now():
                    return response.Response({'error': 'Cuenta bloqueada'}, status=status.HTTP_403_FORBIDDEN)
                user.is_locked = False
                user.failed_attempts = 0
                user.save()
            
            user.failed_attempts = 0
            user.save()
            
            # Logic: If MFA enabled, return temporary token for MFA verification, else return final tokens
            if user.mfa_enabled:
                return response.Response({'message': 'MFA required', 'user_id': user.id})
            
            refresh = RefreshToken.for_user(user)
            return response.Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        
        # Handle failed attempt
        user = CustomUser.objects.filter(email=serializer.data['email']).first()
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= 3:
                user.is_locked = True
                user.lockout_until = timezone.now() + timezone.timedelta(minutes=15)
            user.save()
            
        return response.Response({'error': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

class MFAVerifyView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')
        user = CustomUser.objects.get(id=user_id)
        
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp):
            refresh = RefreshToken.for_user(user)
            return response.Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        
        return response.Response({'error': 'Código OTP inválido'}, status=status.HTTP_401_UNAUTHORIZED)
