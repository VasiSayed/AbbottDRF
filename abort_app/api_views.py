# abort_app/api_views.py
from __future__ import annotations
from datetime import datetime, time as dtime, timedelta

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db.models import Count

from .models import (
    UserProfile, Event, EventExpert, EventJoin, JoinLog, GeneratedReport
)
from .serializers import (
    UserProfileSerializer, EventSerializer, EventExpertSerializer,
    EventJoinSerializer, JoinLogSerializer, GeneratedReportSerializer,EventJoinWithUserSerializer
)

# api_views.py  (add imports near the top)
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

class LogoutView(APIView):
    """
    POST /api/auth/logout/
    Body: { "refresh": "<refresh token>" }  # or "refresh_token"
    Always returns 200 with {ok: true}. If the blacklist app is enabled,
    the refresh token is blacklisted.
    """
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # no CSRF/session needed

    def post(self, request):
        refresh = request.data.get("refresh") or request.data.get("refresh_token")
        if refresh:
            try:
                token = RefreshToken(refresh)
                # Blacklist only if the app is installed
                if "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS:
                    token.blacklist()
            except Exception:
                # invalid/expired token → still respond ok to avoid leaking info
                pass

        return Response({"ok": True})


class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)


class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.select_related("user")
    serializer_class = UserProfileSerializer
    # permission_classes = [permissions.IsAdminUser]

def _client_meta(request):
    fwd = request.META.get("HTTP_X_FORWARDED_FOR")
    ip = fwd.split(",")[0].strip() if fwd else request.META.get("REMOTE_ADDR")
    ua = request.META.get("HTTP_USER_AGENT", "")
    return ip, ua
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class PasswordResetRequest(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # no CSRF/session

    def post(self, request):
        email = (request.data.get("email") or "").lower().strip()
        if not email:
            return Response({"ok": False, "message": "email is required"}, status=400)

        user = User.objects.filter(email=email).first()
        # Always return ok to avoid account enumeration
        if not user:
            return Response({"ok": True})

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)

        # Build a frontend URL if you have one
        frontend = getattr(settings, "FRONTEND_URL", "")
        reset_url = f"{frontend}/reset-password?uid={uid}&token={token}" if frontend else None

        # TODO: in production, send 'reset_url' by email

        # For dev, return token so you can test without email
        return Response({"ok": True, "uid": uid, "token": token, "reset_url": reset_url})



class PasswordResetConfirm(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # no CSRF/session

    def post(self, request):
        uid = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")

        if not (uid and token and new_password):
            return Response({"ok": False, "message": "uid, token and new_password are required"}, status=400)

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
        except Exception:
            return Response({"ok": False, "message": "Invalid reset link"}, status=400)

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({"ok": False, "message": "Invalid or expired token"}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({"ok": True})


class EventViewSet(viewsets.ModelViewSet):
    """
    Public can GET list/detail (React UI).
    Admin/staff can create/update/delete.
    lookup_field is 'code' so /api/events/<code>/ works.
    """
    serializer_class = EventSerializer               
    permission_classes = [IsAdminOrReadOnly]
    lookup_field = "code"

    # ✅ KEY: skip JWT/authentication for public reads even if Authorization header is present
    def get_authenticators(self):
        # Treat these as public endpoints
        public_actions = {"list", "retrieve", "upcoming", "featured", "open"}
        if getattr(self, "action", None) in public_actions or self.request.method in permissions.SAFE_METHODS:
            return []  # no authentication → request.user will be AnonymousUser
        return super().get_authenticators()

    def get_queryset(self):
        qs = Event.objects.all().prefetch_related("experts")
        status_q = self.request.query_params.get("status")
        limit_q = self.request.query_params.get("limit")
        now = timezone.now()

        if status_q == "upcoming":
            qs = qs.filter(start_at__gt=now).order_by("start_at")
        elif status_q == "live":
            qs = qs.filter(start_at__lte=now + timedelta(minutes=15), end_at__gte=now).order_by("start_at")
        elif status_q == "past":
            qs = qs.filter(end_at__lt=now).order_by("-end_at")
        else:
            qs = qs.order_by("-start_at")

        if limit_q:
            try:
                qs = qs[: max(0, int(limit_q))]
            except ValueError:
                pass
        return qs

    @action(
        detail=True,
        methods=["post"],
        permission_classes=[permissions.AllowAny],
        authentication_classes=[],  # ✅ no auth for open()
    )
    def open(self, request, code=None):
        ok, link_or_msg, ev = Event.attempt_open_for_code(
            code=code,
            user=request.user if request.user.is_authenticated else None,
            request=request,
        )
        if ok:
            return Response({
                "ok": True,
                "link": link_or_msg,
                "event": EventSerializer(ev, context={"request": request}).data
            })
        return Response(
            {
                "ok": False,
                "message": link_or_msg,
                "event": EventSerializer(ev, context={"request": request}).data if ev else None,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(
        detail=False,
        methods=["get"],
        permission_classes=[permissions.IsAdminUser],  # ✅ no auth for upcoming
    )

    def upcoming(self, request):
        limit_q = request.query_params.get("limit", "5")
        try:
            limit = max(1, min(50, int(limit_q)))
        except ValueError:
            limit = 5
        qs = Event.objects.filter(start_at__gt=timezone.now()).order_by("start_at")[:limit]
        data = EventSerializer(qs, many=True, context={"request": request}).data
        return Response({"results": data, "count": len(data)})

    @action(
        detail=False,
        methods=["get"],
permission_classes=[permissions.IsAdminUser],  # ✅ no auth for featured
    )
    def featured(self, request):
        code = request.query_params.get("code")
        if not code:
            return Response({"detail": "code is required"}, status=400)
        ev = Event.current_for_code(code)
        if not ev:
            return Response({"detail": "No event found for this code"}, status=404)
        return Response(EventSerializer(ev, context={"request": request}).data)

    @action(detail=True, methods=["get"], permission_classes=[])
    def analytics(self, request, code=None):
        """
        GET /api/events/{code}/analytics/
        Returns per-event analytics:
          - registrations (non-staff)
          - attempts by status, totals
          - daily attempts (last 14 days) per status
          - speciality distribution, top hospitals
          - recent logs (50)
        """
        event = self.get_object()

        # registrations (exclude staff)
        reg_qs = EventJoin.objects.filter(event=event, user__is_staff=False)
        total_regs = reg_qs.count()

        # attempts
        logs_qs = JoinLog.objects.filter(event=event)
        by_status = dict(
            logs_qs.values("status").annotate(c=Count("id")).values_list("status", "c")
        )
        attempts_total = logs_qs.count()
        attempts_success = by_status.get(JoinLog.Status.SUCCESS, 0)
        attempts_refused = by_status.get(JoinLog.Status.REFUSED, 0)
        attempts_error = by_status.get(JoinLog.Status.ERROR, 0)

        # last 14 days split by status
        now = timezone.now()
        days = [now.date() - timedelta(days=i) for i in range(13, -1, -1)]
        labels = [d.strftime("%b %d") for d in days]

        def _count_for(day, status):
            start = timezone.make_aware(datetime.combine(day, dtime.min))
            end = start + timedelta(days=1)
            return logs_qs.filter(occurred_at__gte=start, occurred_at__lt=end, status=status).count()

        daily_success = [_count_for(d, JoinLog.Status.SUCCESS) for d in days]
        daily_refused = [_count_for(d, JoinLog.Status.REFUSED) for d in days]
        daily_error   = [_count_for(d, JoinLog.Status.ERROR)   for d in days]

        # speciality & hospital breakdowns (registrants only)
        regs_users = UserProfile.objects.filter(user__event_joins__event=event, user__is_staff=False)
        spec_rows = (
            regs_users.exclude(speciality__exact="")
                      .values("speciality")
                      .annotate(count=Count("id"))
                      .order_by("-count")
        )
        hosp_rows = (
            regs_users.exclude(hospital__exact="")
                      .values("hospital")
                      .annotate(count=Count("id"))
                      .order_by("-count")[:10]
        )

        # recent logs
        recent_logs = logs_qs.select_related("user").order_by("-occurred_at")[:50]
        recent_logs_data = JoinLogSerializer(recent_logs, many=True).data

        return Response({
            "event": EventSerializer(event, context={"request": request}).data,
            "registrations": {"total": total_regs},
            "attempts": {
                "total": attempts_total,
                "success": attempts_success,
                "refused": attempts_refused,
                "error": attempts_error,
            },
            "daily": {
                "labels": labels,
                "success": daily_success,
                "refused": daily_refused,
                "error": daily_error,
            },
            "speciality": [{"speciality": r["speciality"], "count": r["count"]} for r in spec_rows],
            "hospitals_top10": [{"hospital": r["hospital"], "count": r["count"]} for r in hosp_rows],
            "recent_logs": recent_logs_data,
        })

    @action(
        detail=True,
        methods=["post"],
        url_path="join",
        permission_classes=[permissions.IsAuthenticated],
    )
    def join(self, request, code=None):
        """
        POST /api/events/{code}/join/
        Authenticated join: allowed from 15 minutes before start until end.
        Creates EventJoin and JoinLog; returns the event link on success.
        """
        ip, ua = _client_meta(request)
        user = request.user

        try:
            event = self.get_object()  # lookup_field='code'
        except Exception:
            # unknown code → refused
            JoinLog.objects.create(
                event=None,
                user=user,
                status=JoinLog.Status.REFUSED,
                message=f"Unknown event code: {code}",
                ip=ip,
                user_agent=ua,
            )
            return Response({"ok": False, "message": "Event not found."}, status=404)

        now = timezone.now()
        window_opens = event.start_at - timedelta(minutes=15)
        window_ok = window_opens <= now <= event.end_at

        if not window_ok:
            JoinLog.objects.create(
                event=event,
                user=user,
                status=JoinLog.Status.REFUSED,
                message="Outside join window (allowed 15 min before start until end).",
                ip=ip,
                user_agent=ua,
            )
            return Response(
                {
                    "ok": False,
                    "message": "You can join from 15 minutes before the start time until the event ends.",
                    "start_at": event.start_at,
                    "end_at": event.end_at,
                    "window_opens_at": window_opens,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not event.link:
            JoinLog.objects.create(
                event=event,
                user=user,
                status=JoinLog.Status.ERROR,
                message="Missing event link.",
                ip=ip,
                user_agent=ua,
            )
            return Response(
                {"ok": False, "message": "Event link is not configured."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # create or keep the user's registration
        if not user.is_staff:
            EventJoin.objects.get_or_create(user=user, event=event)

        # success log
        JoinLog.objects.create(
            event=event,
            user=user,
            status=JoinLog.Status.SUCCESS,
            message="Authenticated join granted.",
            ip=ip,
            user_agent=ua,
        )

        return Response(
            {
                "ok": True,
                "link": event.link,
                "event": EventSerializer(event, context={"request": request}).data,
            },
            status=status.HTTP_200_OK,
        )


    @action(
        detail=True,
        methods=["post"],
        url_path="register",
        permission_classes=[permissions.AllowAny],
        authentication_classes=[],   
    )
    def register(self, request, code=None):
        """
        POST /api/events/{code}/register/
        Public registration that creates user+profile, returns JWT tokens,
        and immediately attempts to join (15 min before start → end).
        Accepts optional 'password' in payload; otherwise uses a temp password.
        """
        data = request.data or {}

        required = [
            "name", "email", "mobile", "hospital", "speciality",
            "accept_policy", "accept_recording",
        ]
        for f in required:
            v = data.get(f, "")
            if isinstance(v, str):
                v = v.strip()
            if v in ("", None):
                return Response({"ok": False, "message": f"{f} is required"}, status=400)

        if not data.get("accept_policy") or not data.get("accept_recording"):
            return Response({"ok": False, "message": "Consent is required"}, status=400)

        email = data["email"].lower().strip()

        # If user exists → tell client to login
        if User.objects.filter(email=email).exists():
            return Response(
                {
                    "ok": False,
                    "reason": "account_exists",
                    "message": "Account already exists. Please login to continue.",
                },
                status=409,
            )

        # Choose password (prefer client-provided)
        raw_password = (data.get("password") or "").strip()
        if not raw_password:
            # Prefer a configurable static value in dev, else generate securely
            raw_password = getattr(settings, "DEFAULT_TEMP_PASSWORD", "") or get_random_string(12)
            # NOTE: do NOT ship with a weak hardcoded password in production.

        # Create user
        user = User.objects.create_user(
            username=email,
            email=email,
            first_name=data.get("name", "").strip(),
            password=raw_password,
        )

        # Create/update profile
        UserProfile.objects.update_or_create(
            user=user,
            defaults={
                "hospital": data.get("hospital", "").strip(),
                "speciality": data.get("speciality", "").strip(),
                "phone": data.get("mobile", "").strip(),
            },
        )

        # Issue JWT tokens so the browser can act as the user immediately
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        # Attempt the join with the same window rule
        ip, ua = _client_meta(request)
        event = self.get_object()
        now = timezone.now()
        window_opens = event.start_at - timedelta(minutes=15)
        window_ok = window_opens <= now <= event.end_at

        link = None
        message = None
        status_code = status.HTTP_200_OK
        log_status = JoinLog.Status.REFUSED
        log_msg = "Registered but outside join window."

        if not event.link:
            message = "Event link is not configured."
            log_status = JoinLog.Status.ERROR
            log_msg = message
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        elif window_ok:
            EventJoin.objects.get_or_create(user=user, event=event)
            link = event.link
            log_status = JoinLog.Status.SUCCESS
            log_msg = "Registered and joined."
        else:
            message = "You can join from 15 minutes before the start time until the event ends."
            status_code = status.HTTP_400_BAD_REQUEST

        JoinLog.objects.create(
            event=event, user=user, status=log_status, message=log_msg, ip=ip, user_agent=ua
        )

        return Response(
            {
                "ok": bool(link),
                "link": link,
                "message": message,
                # Tokens let the frontend act as the user; no need to reveal password.
                "tokens": {"access": access, "refresh": str(refresh)},
                "event": EventSerializer(event, context={"request": request}).data,
            },
            status=status_code,
        )



class EventExpertViewSet(viewsets.ModelViewSet):
    queryset = EventExpert.objects.select_related("event").all()
    serializer_class = EventExpertSerializer
    permission_classes = [IsAdminOrReadOnly]



# --- add near your other imports ---
from django.db.models import Q

# --- paste anywhere below your other APIViews ---
# --- Non-staff users + join counters ---
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from django.utils import timezone
from datetime import timedelta

class NonStaffUsersView(APIView):
    """
    GET /api/users/non-staff/?limit=100&offset=0
    Returns non-staff users (paged) + counts for users and joins.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        now = timezone.now()
        qs = User.objects.filter(is_staff=False).order_by("-date_joined")

        # user counters
        count_total = qs.count()
        last_7_days  = qs.filter(date_joined__gte=now - timedelta(days=7)).count()
        last_30_days = qs.filter(date_joined__gte=now - timedelta(days=30)).count()

        # joins counters (exclude staff)
        joins_qs = EventJoin.objects.filter(user__is_staff=False)
        joins_total      = joins_qs.count()
        joins_last_7     = joins_qs.filter(joined_at__gte=now - timedelta(days=7)).count()
        joins_last_30    = joins_qs.filter(joined_at__gte=now - timedelta(days=30)).count()

        # events live now
        live_now = Event.objects.filter(start_at__lte=now, end_at__gte=now).count()

        # very small paging (optional)
        try:
            limit = max(1, min(1000, int(request.query_params.get("limit", "100"))))
        except ValueError:
            limit = 100
        try:
            offset = max(0, int(request.query_params.get("offset", "0")))
        except ValueError:
            offset = 0

        page = qs[offset: offset + limit]
        results = [
            {
                "id": u.id,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "email": u.email,
                "date_joined": u.date_joined,
            }
            for u in page
        ]

        return Response({
            "users": {
                "count_total": count_total,
                "last_7_days": last_7_days,
                "last_30_days": last_30_days,
                "limit": limit,
                "offset": offset,
                "results": results,
            },
            "joins": {
                "total": joins_total,
                "last_7_days": joins_last_7,
                "last_30_days": joins_last_30,
            },
            "events": {
                "live_now": live_now,
            },
        })


class EventJoinViewSet(viewsets.ModelViewSet):
    serializer_class = EventJoinWithUserSerializer   # <- changed
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        qs = (
            EventJoin.objects
            .select_related("user", "user__profile", "event")
            .all()
            .exclude(user__is_staff=True)
        )
        # filters: ?event=<uuid>&code=<code>&date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
        event_id = self.request.query_params.get("event")
        code = self.request.query_params.get("code")
        date_from = self.request.query_params.get("date_from")
        date_to = self.request.query_params.get("date_to")
        if event_id:
            qs = qs.filter(event_id=event_id)
        if code:
            qs = qs.filter(event__code=code)
        if date_from:
            qs = qs.filter(joined_at__date__gte=date_from)
        if date_to:
            qs = qs.filter(joined_at__date__lte=date_to)
        return qs
    
    @action(
        detail=True,
        methods=["get"],
        url_path="registrants",
        permission_classes=[permissions.IsAdminUser],
    )
    def registrants(self, request, code=None):
        """
        GET /api/events/{code}/registrants/   (staff)
        Returns:
          - registrations_total (EventJoin count, non-staff)
          - attempts (JoinLog totals split by status)
          - registrations: list[EventJoinWithUserSerializer] (user + profile)
        """
        event = self.get_object()

        regs = (
            EventJoin.objects
            .filter(event=event, user__is_staff=False)
            .select_related("user", "user__profile", "event")
            .order_by("-joined_at")
        )

        # JoinLog counts for this event
        logs_qs = JoinLog.objects.filter(event=event)
        by_status = dict(
            logs_qs.values("status")
                   .annotate(c=Count("id"))
                   .values_list("status", "c")
        )

        payload = {
            "event": EventSerializer(event, context={"request": request}).data,
            "registrations_total": regs.count(),          # <-- count by EventJoin
            "attempts": {
                "total":   logs_qs.count(),
                "success": by_status.get(JoinLog.Status.SUCCESS, 0),
                "refused": by_status.get(JoinLog.Status.REFUSED, 0),
                "error":   by_status.get(JoinLog.Status.ERROR, 0),
            },
            "registrations": EventJoinWithUserSerializer(regs, many=True).data,
        }
        return Response(payload)




class JoinLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = JoinLogSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        qs = JoinLog.objects.select_related("user", "event").all()
        # filters: ?event=<uuid>&code=<code>&status=SUCCESS|REFUSED|ERROR&date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
        event_id = self.request.query_params.get("event")
        code = self.request.query_params.get("code")
        status_q = self.request.query_params.get("status")
        date_from = self.request.query_params.get("date_from")
        date_to = self.request.query_params.get("date_to")
        if event_id:
            qs = qs.filter(event_id=event_id)
        if code:
            qs = qs.filter(event__code=code)
        if status_q:
            qs = qs.filter(status=status_q)
        if date_from:
            qs = qs.filter(occurred_at__date__gte=date_from)
        if date_to:
            qs = qs.filter(occurred_at__date__lte=date_to)
        return qs.order_by("-occurred_at")


class GeneratedReportViewSet(viewsets.ModelViewSet):
    queryset = GeneratedReport.objects.select_related("created_by").all()
    serializer_class = GeneratedReportSerializer
    permission_classes = [permissions.IsAdminUser]


from datetime import timedelta
from django.utils import timezone
from django.db.models import Count
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions

from .models import Event, EventJoin, UserProfile, GeneratedReport

User = get_user_model()


# class AnalyticsDashboardView(APIView):
#     """
#     GET /api/analytics/dashboard/  (staff)
#     Global metrics & series used by the admin dashboard.
#     """
#     permission_classes = [permissions.IsAdminUser]

#     def get(self, request):
#         now = timezone.now()

#         # Totals
#         total_users = User.objects.filter(is_staff=False).count()

#         # All EventJoin rows (some users may register for multiple events)
#         total_event_joins = EventJoin.objects.filter(user__is_staff=False).count()

#         # Distinct users who have at least one registration
#         total_registrations = (
#             EventJoin.objects.filter(user__is_staff=False)
#             .values("user_id").distinct().count()
#         )

#         upcoming_meetings = Event.objects.filter(start_at__gt=now).count()

#         registrations_last_7_days = EventJoin.objects.filter(
#             user__is_staff=False,
#             joined_at__gte=now - timedelta(days=7),
#         ).count()

#         reports_last_month = GeneratedReport.objects.filter(
#             created_at__gte=now - timedelta(days=30)
#         ).count()

#         # Daily series (last 14 days) from EventJoin.joined_at
#         days = [now.date() - timedelta(days=i) for i in range(13, -1, -1)]
#         daily_labels = [d.strftime("%b %d") for d in days]
#         daily_counts = [
#             EventJoin.objects.filter(
#                 user__is_staff=False,
#                 joined_at__date=d
#             ).count()
#             for d in days
#         ]

#         # Speciality distribution among users who have registered at least once
#         registrant_profiles = (
#             UserProfile.objects
#             .filter(user__is_staff=False, user__event_joins__isnull=False)
#             .exclude(speciality__isnull=True)
#             .exclude(speciality__exact="")
#         )
#         spec_rows = (
#             registrant_profiles
#             .values("speciality")
#             .annotate(count=Count("user_id", distinct=True))
#             .order_by("-count")
#         )
#         spec_labels = [r["speciality"] for r in spec_rows]
#         spec_counts = [r["count"] for r in spec_rows]

#         return Response({
#             "cards": {
#                 # distinct users who registered at least once
#                 "total_registrations": total_registrations,
#                 # optional extras if you want them on the UI:
#                 "total_users": total_users,
#                 "total_event_joins": total_event_joins,

#                 "upcoming_meetings": upcoming_meetings,
#                 "registrations_last_7_days": registrations_last_7_days,
#                 "reports_last_month": reports_last_month,
#             },
#             "daily": {"labels": daily_labels, "counts": daily_counts},
#             "speciality": {"labels": spec_labels, "counts": spec_counts},
#         })



# abort_app/api_views.py  (analytics section)

from django.db.models import Count, Q

class AnalyticsDashboardView(APIView):
    """
    GET /api/analytics/dashboard/    (staff)
    Global KPI cards + series for the admin dashboard.
    Also returns a short per-event summary (last 20 events) with
    registrations + attempts split by status.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        now = timezone.now()

        # ----- KPI cards -----
        total_users = User.objects.filter(is_staff=False).count()
        total_event_joins = EventJoin.objects.filter(user__is_staff=False).count()
        total_registrations = (
            EventJoin.objects.filter(user__is_staff=False)
            .values("user_id").distinct().count()
        )
        upcoming_meetings = Event.objects.filter(start_at__gt=now).count()
        registrations_last_7_days = EventJoin.objects.filter(
            user__is_staff=False, joined_at__gte=now - timedelta(days=7)
        ).count()
        reports_last_month = GeneratedReport.objects.filter(
            created_at__gte=now - timedelta(days=30)
        ).count()

        # ----- Daily series (last 14 days) from EventJoin.joined_at -----
        days = [now.date() - timedelta(days=i) for i in range(13, -1, -1)]
        daily_labels = [d.strftime("%b %d") for d in days]
        daily_counts = [
            EventJoin.objects.filter(user__is_staff=False, joined_at__date=d).count()
            for d in days
        ]

        # ----- Speciality distribution (distinct registrants only) -----
        registrant_profiles = (
            UserProfile.objects
            .filter(user__is_staff=False, user__event_joins__isnull=False)
            .exclude(speciality__isnull=True)
            .exclude(speciality__exact="")
        )
        spec_rows = (
            registrant_profiles
            .values("speciality")
            .annotate(count=Count("user_id", distinct=True))
            .order_by("-count")
        )
        spec_labels = [r["speciality"] for r in spec_rows]
        spec_counts = [r["count"] for r in spec_rows]

        # ----- Short per-event summary (last 20) -----
        events = list(Event.objects.order_by("-start_at")[:20])
        event_ids = [e.id for e in events]

        # registrations (exclude staff)
        regs_by_event = dict(
            EventJoin.objects
            .filter(event_id__in=event_ids, user__is_staff=False)
            .values("event_id")
            .annotate(c=Count("id"))
            .values_list("event_id", "c")
        )

        # logs by status
        logs_qs = JoinLog.objects.filter(event_id__in=event_ids)
        totals_by_event   = dict(logs_qs.values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))
        success_by_event  = dict(logs_qs.filter(status=JoinLog.Status.SUCCESS).values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))
        refused_by_event  = dict(logs_qs.filter(status=JoinLog.Status.REFUSED).values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))
        error_by_event    = dict(logs_qs.filter(status=JoinLog.Status.ERROR).values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))

        events_summary = []
        for ev in events:
            events_summary.append({
                "event": EventSerializer(ev, context={"request": request}).data,
                "registrations": {"total": regs_by_event.get(ev.id, 0)},
                "attempts": {
                    "total":   totals_by_event.get(ev.id, 0),
                    "success": success_by_event.get(ev.id, 0),
                    "refused": refused_by_event.get(ev.id, 0),
                    "error":   error_by_event.get(ev.id, 0),
                },
            })

        return Response({
            "cards": {
                "total_registrations": total_registrations,  # distinct users who registered at least once
                "total_users": total_users,
                "total_event_joins": total_event_joins,
                "upcoming_meetings": upcoming_meetings,
                "registrations_last_7_days": registrations_last_7_days,
                "reports_last_month": reports_last_month,
            },
            "daily": {"labels": daily_labels, "counts": daily_counts},
            "speciality": {"labels": spec_labels, "counts": spec_counts},
            "events_summary": events_summary,
        })


class EventsAnalyticsListView(APIView):
    """
    GET /api/analytics/events/        (staff)
    Per-event analytics for *all* (or filtered) events.

    Query params:
      - code=<event code>            (optional, filter to one)
      - date_from=YYYY-MM-DD         (optional, filter logs range)
      - date_to=YYYY-MM-DD           (optional)
      - include_logs=true|false      (optional, default false)
      - logs_limit=10                (optional, default 10)
      - status=SUCCESS|REFUSED|ERROR (optional, only affects returned logs)

    Response:
      {
        "count": N,
        "results": [
          {
            "event": {...},
            "registrations": {"total": <non-staff EventJoin count>},
            "attempts": {
              "total": <JoinLog>,
              "success": <JoinLog SUCCESS>,
              "refused": <JoinLog REFUSED>,
              "error": <JoinLog ERROR>
            },
            "recent_logs": [...]   # only if include_logs=true
          },
          ...
        ]
      }
    """
    # permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        qs = Event.objects.all().order_by("-start_at").prefetch_related("experts")

        code = request.query_params.get("code")
        if code:
            qs = qs.filter(code=code)

        date_from = request.query_params.get("date_from")
        date_to = request.query_params.get("date_to")
        status_filter = request.query_params.get("status")
        include_logs = str(request.query_params.get("include_logs", "")).lower() in {"1", "true", "yes"}
        try:
            logs_limit = max(1, min(200, int(request.query_params.get("logs_limit", "10"))))
        except ValueError:
            logs_limit = 10

        events = list(qs)
        event_ids = [e.id for e in events]

        regs_by_event = dict(
            EventJoin.objects
            .filter(event_id__in=event_ids, user__is_staff=False)
            .values("event_id")
            .annotate(c=Count("id"))
            .values_list("event_id", "c")
        )

        # Base logs queryset (optionally date-filtered)
        logs_qs = JoinLog.objects.filter(event_id__in=event_ids)
        if date_from:
            logs_qs = logs_qs.filter(occurred_at__date__gte=date_from)
        if date_to:
            logs_qs = logs_qs.filter(occurred_at__date__lte=date_to)

        # Counts by status
        totals_by_event   = dict(logs_qs.values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))
        success_by_event  = dict(logs_qs.filter(status=JoinLog.Status.SUCCESS).values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))
        refused_by_event  = dict(logs_qs.filter(status=JoinLog.Status.REFUSED).values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))
        error_by_event    = dict(logs_qs.filter(status=JoinLog.Status.ERROR).values("event_id").annotate(c=Count("id")).values_list("event_id", "c"))

        results = []
        for ev in events:
            item = {
                "event": EventSerializer(ev, context={"request": request}).data,
                "registrations": {"total": regs_by_event.get(ev.id, 0)},
                "attempts": {
                    "total":   totals_by_event.get(ev.id, 0),
                    "success": success_by_event.get(ev.id, 0),
                    "refused": refused_by_event.get(ev.id, 0),
                    "error":   error_by_event.get(ev.id, 0),
                },
            }

            if include_logs:
                rl_qs = JoinLog.objects.filter(event=ev)
                if date_from:
                    rl_qs = rl_qs.filter(occurred_at__date__gte=date_from)
                if date_to:
                    rl_qs = rl_qs.filter(occurred_at__date__lte=date_to)
                if status_filter in {JoinLog.Status.SUCCESS, JoinLog.Status.REFUSED, JoinLog.Status.ERROR}:
                    rl_qs = rl_qs.filter(status=status_filter)
                rl_qs = rl_qs.select_related("user").order_by("-occurred_at")[:logs_limit]
                item["recent_logs"] = JoinLogSerializer(rl_qs, many=True).data

            results.append(item)

        return Response({"count": len(results), "results": results})

