# abort_app/api_auth.py
from django.contrib.auth import get_user_model
from rest_framework import serializers, exceptions
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Accepts either:
      { "username": "...", "password": "..." }
    or
      { "email": "...", "password": "..." }
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # allow email-based login without sending username
        self.fields['email'] = serializers.EmailField(required=False)
        self.fields[self.username_field].required = False  # 'username' usually

    def validate(self, attrs):
        User = get_user_model()

        username = attrs.get(self.username_field)
        email = attrs.get('email')
        password = attrs.get('password')

        # If only email was provided, translate it to the username_field
        if not username and email:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                attrs[self.username_field] = user.get_username()
            else:
                # mimic default invalid-credentials error
                raise exceptions.AuthenticationFailed(
                    "No active account found with the given credentials"
                )

        # Now let SimpleJWT do the normal username/password validation
        return super().validate(attrs)


class EmailOrUsernameTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailOrUsernameTokenObtainPairSerializer


class MeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        u = request.user
        prof = getattr(u, "profile", None)
        return Response({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "is_staff": u.is_staff,
            "profile": {
                "hospital": getattr(prof, "hospital", ""),
                "speciality": getattr(prof, "speciality", ""),
                "phone": getattr(prof, "phone", ""),
            } if prof else None
        })
