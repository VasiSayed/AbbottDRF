# abort_app/serializers.py
from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import (
    UserProfile,
    Event,
    EventExpert,
    EventJoin,
    JoinLog,
    GeneratedReport,
)

User = get_user_model()


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ["id", "user", "hospital", "speciality", "phone"]
        read_only_fields = ["id"]


class EventExpertSerializer(serializers.ModelSerializer):
    photo_url = serializers.SerializerMethodField()

    class Meta:
        model = EventExpert
        fields = [
            "id",
            "event",
            "name",
            "role",
            "photo",
            "photo_url",
            "description",
            "order",
        ]
        read_only_fields = ["id"]

    def get_photo_url(self, obj):
        request = self.context.get("request")
        if obj.photo and request:
            return request.build_absolute_uri(obj.photo.url)
        return None

    def validate(self, attrs):
        # Enforce <= 5 experts per event
        event = attrs.get("event") or (self.instance.event if self.instance else None)
        if event:
            qs = EventExpert.objects.filter(event=event)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.count() >= 5:
                raise serializers.ValidationError("Maximum 5 experts allowed per event.")
        return attrs


class EventSerializer(serializers.ModelSerializer):
    experts = EventExpertSerializer(many=True, read_only=True)
    banner_url = serializers.SerializerMethodField()
    color_hex = serializers.SerializerMethodField()
    is_live_now = serializers.SerializerMethodField()
    window_opens_at = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = [
            "id",
            "code",
            "banner",
            "banner_url",
            "title",
            "description",
            "link",
            "color",
            "color_hex",
            "start_at",
            "end_at",
            "is_current",
            "created_at",
            "updated_at",
            "is_live_now",
            "window_opens_at",
            "experts",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "is_live_now",
            "window_opens_at",
            "experts",
        ]

    def get_banner_url(self, obj):
        request = self.context.get("request")
        if obj.banner and request:
            return request.build_absolute_uri(obj.banner.url)
        return None

    def get_color_hex(self, obj):
        if obj.color is None:
            return None
        return f"#{int(obj.color):06x}"

    def get_is_live_now(self, obj):
        return obj.is_live_now()

    def get_window_opens_at(self, obj):
        return obj.window_opens_at

    def validate(self, attrs):
        # Only one is_current per code
        is_current = attrs.get("is_current", getattr(self.instance, "is_current", False))
        code = attrs.get("code", getattr(self.instance, "code", None))
        if is_current and code:
            qs = Event.objects.filter(code=code, is_current=True)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise serializers.ValidationError(
                    {"is_current": f"Only one 'current' event allowed for code '{code}'."}
                )

        # End must be after start
        start_at = attrs.get("start_at", getattr(self.instance, "start_at", None))
        end_at = attrs.get("end_at", getattr(self.instance, "end_at", None))
        if start_at and end_at and end_at <= start_at:
            raise serializers.ValidationError({"end_at": "End must be after start."})
        return attrs


class EventJoinSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventJoin
        fields = ["id", "user", "event", "joined_at"]
        read_only_fields = ["id", "joined_at"]


class JoinLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = JoinLog
        fields = ["id", "user", "event", "status", "message", "ip", "user_agent", "occurred_at"]
        read_only_fields = ["id", "occurred_at"]


class GeneratedReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = GeneratedReport
        fields = [
            "id",
            "title",
            "report_type",
            "start_at",
            "end_at",
            "include_all",
            "created_by",
            "created_at",
            "file",
        ]
        read_only_fields = ["id", "created_at"]


# Small nested “refs” used in EventJoinWithUserSerializer
class UserRefSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email")


class UserProfileRefSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("hospital", "speciality", "phone")


class EventJoinWithUserSerializer(serializers.ModelSerializer):
    user = UserRefSerializer(read_only=True)
    profile = UserProfileRefSerializer(source="user.profile", read_only=True)
    event_code = serializers.CharField(source="event.code", read_only=True)
    event_title = serializers.CharField(source="event.title", read_only=True)

    class Meta:
        model = EventJoin
        fields = (
            "id",
            "joined_at",
            "event",        # FK UUID
            "event_code",
            "event_title",
            "user",
            "profile",
        )
