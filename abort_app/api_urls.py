from django.urls import path, include
from rest_framework.routers import DefaultRouter
from abort_app.api_views import (
    EventViewSet, EventExpertViewSet, EventJoinViewSet, JoinLogViewSet,
    GeneratedReportViewSet, AnalyticsDashboardView,
    PasswordResetRequest, PasswordResetConfirm, EventsAnalyticsListView ,UserProfileViewSet ,NonStaffUsersView
    ,LogoutView# if you added these
)


router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"users", UserProfileViewSet, basename="users")
router.register(r"experts", EventExpertViewSet, basename="expert")
router.register(r"joins", EventJoinViewSet, basename="join")
router.register(r"logs", JoinLogViewSet, basename="log")
router.register(r"reports", GeneratedReportViewSet, basename="report")

urlpatterns = [
    path("", include(router.urls)),
    path("analytics/dashboard/", AnalyticsDashboardView.as_view(), name="analytics-dashboard"),
    path("analytics/events/", EventsAnalyticsListView.as_view(), name="analytics-events"),
    path("auth/password/reset/", PasswordResetRequest.as_view()),
    path("auth/password/reset/confirm/", PasswordResetConfirm.as_view()),
    path("user-non-staff/", NonStaffUsersView.as_view(), name="non-staff-users"),
    path("api/auth/logout/", LogoutView.as_view(), name="auth-logout"),

]
