from __future__ import annotations
import uuid
from datetime import timedelta
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

UserRef = settings.AUTH_USER_MODEL


class UserProfile(models.Model):
    user = models.OneToOneField(UserRef, on_delete=models.CASCADE, related_name="profile")
    hospital = models.CharField(max_length=200, blank=True)
    speciality = models.CharField(max_length=120, blank=True)
    phone = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return f"{self.user.username} ({self.speciality})"


class Event(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=120, unique=True)

    banner = models.ImageField(
        upload_to="events/banners/", blank=True, null=True, db_column="logo"
    )

    title = models.CharField(max_length=200,null=True,blank=True)
    description = models.TextField(blank=True)
    link = models.URLField(help_text="Where attendees are sent when the session is live")
    color = models.BigIntegerField(null=True, blank=True)
    start_at = models.DateTimeField()
    end_at = models.DateTimeField()
    is_current = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "evt_event"
        indexes = [
            models.Index(fields=["start_at"]),
            models.Index(fields=["end_at"]),
            models.Index(fields=["code", "is_current"]),
        ]
        ordering = ["-start_at"]

    def __str__(self):
        return f"{self.code} | {self.title} ({self.start_at} → {self.end_at})"

    def clean(self):
        if self.end_at <= self.start_at:
            raise ValidationError({"end_at": "End must be after start."})

    @property
    def window_opens_at(self):
        return self.start_at - timedelta(minutes=15)

    def is_live_now(self, now=None) -> bool:
        now = now or timezone.now()
        return (self.start_at - timedelta(minutes=15)) <= now <= self.end_at

    @classmethod
    def current_for_code(cls, code: str) -> "Event | None":
        now = timezone.now()
        window_start = now + timedelta(minutes=15)
        q = cls.objects.filter(code=code, start_at__lte=window_start, end_at__gte=now)
        featured = q.filter(is_current=True).first()
        return featured or q.order_by("-start_at").first()

    @classmethod
    def attempt_open_for_code(cls, *, code: str, user=None, request=None):
        """
        Returns (ok, link_or_msg, event_or_none)
        """
        now = timezone.now()
        ev_live = (
            cls.objects.filter(
                code=code, start_at__lte=now + timedelta(minutes=15), end_at__gte=now
            )
            .order_by("-start_at")
            .first()
        )
        if ev_live and (ev_live.start_at - timedelta(minutes=15)) <= now <= ev_live.end_at:
            with transaction.atomic():
                if user:
                    EventJoin.objects.get_or_create(user=user, event=ev_live)
                JoinLog.log(
                    user=user,
                    event=ev_live,
                    status=JoinLog.Status.SUCCESS,
                    message="Opened event link.",
                    request=request,
                )
            return True, ev_live.link, ev_live

        upcoming = (
            cls.objects.filter(code=code, start_at__gt=now).order_by("start_at").first()
        )
        if upcoming:
            opens_at = upcoming.start_at - timedelta(minutes=15)
            msg = (
                "This event isn’t active yet. "
                f"It opens at {timezone.localtime(opens_at).strftime('%b %d, %Y %I:%M %p %Z')}."
            )
            JoinLog.log(
                user=user,
                event=upcoming,
                status=JoinLog.Status.REFUSED,
                message=msg,
                request=request,
            )
            return False, msg, upcoming

        last = (
            cls.objects.filter(code=code, end_at__lt=now).order_by("-end_at").first()
        )
        if last:
            ended = timezone.localtime(last.end_at).strftime("%b %d, %Y %I:%M %p %Z")
            msg = f"This event has ended (ended {ended})."
            JoinLog.log(
                user=user,
                event=last,
                status=JoinLog.Status.REFUSED,
                message=msg,
                request=request,
            )
            return False, msg, last

        msg = f"No event exists for code '{code}'."
        JoinLog.log(
            user=user, event=None, status=JoinLog.Status.REFUSED, message=msg, request=request
        )
        return False, msg, None


class EventExpert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # FK nullable per your request
    event = models.ForeignKey(
        Event, on_delete=models.CASCADE, related_name="experts", null=True, blank=True
    )
    name = models.CharField(max_length=120)
    # NEW (optional) role, e.g. Speaker/Moderator
    role = models.CharField(max_length=120, null=True, blank=True)
    photo = models.ImageField(upload_to="events/experts/")
    description = models.CharField(max_length=255, blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "evt_expert"
        indexes = [models.Index(fields=["event", "order"])]
        ordering = ["order", "name"]
        unique_together = [("event", "name")]

    def __str__(self):
        return f"{self.name} · {self.event.title if self.event_id else '—'}"

    def clean(self):
        # enforce <= 5 experts per event (only when event is set)
        if not self.event_id:
            return
        qs = EventExpert.objects.filter(event_id=self.event_id)
        if self.pk:
            qs = qs.exclude(pk=self.pk)
        if qs.count() >= 5:
            raise ValidationError("Maximum 5 experts allowed per event.")


class EventJoin(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(UserRef, on_delete=models.CASCADE, related_name="event_joins")
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="joins")
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "evt_join"
        unique_together = [("user", "event")]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["event"]),
            models.Index(fields=["joined_at"]),
        ]

    def __str__(self):
        return f"{self.user_id} → {self.event_id} @ {self.joined_at}"


class JoinLog(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "SUCCESS", "Success"
        REFUSED = "REFUSED", "Refused"
        ERROR = "ERROR", "Error"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        UserRef, null=True, blank=True, on_delete=models.SET_NULL, related_name="event_attempt_logs"
    )
    event = models.ForeignKey(
        Event, null=True, blank=True, on_delete=models.SET_NULL, related_name="attempt_logs"
    )
    status = models.CharField(max_length=10, choices=Status.choices)
    message = models.TextField(blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "evt_join_log"
        indexes = [
            models.Index(fields=["status", "occurred_at"]),
            models.Index(fields=["event", "occurred_at"]),
        ]
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"{self.status} @ {self.occurred_at} (ev={self.event_id})"

    @classmethod
    def log(cls, *, user=None, event: Event | None, status: str, message: str = "", request=None) -> "JoinLog":
        ip = None
        ua = ""
        if request:
            ip = (
                request.META.get("REMOTE_ADDR")
                or request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0]
                or None
            )
            ua = request.META.get("HTTP_USER_AGENT", "")
        return cls.objects.create(user=user, event=event, status=status, message=message, ip=ip, user_agent=ua)


class GeneratedReport(models.Model):
    class ReportType(models.TextChoices):
        REGISTRATION = "REGISTRATION", "Registrations"
        EVENT = "EVENT", "Events"
        ANALYTICS = "ANALYTICS", "Analytics"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=20, choices=ReportType.choices)
    start_at = models.DateTimeField(null=True, blank=True)
    end_at = models.DateTimeField(null=True, blank=True)
    include_all = models.BooleanField(default=False)

    created_by = models.ForeignKey(UserRef, on_delete=models.CASCADE, related_name="generated_reports")
    created_at = models.DateTimeField(auto_now_add=True)

    file = models.FileField(upload_to="reports/", null=True, blank=True)

    class Meta:
        db_table = "evt_generated_report"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} ({self.report_type})"
