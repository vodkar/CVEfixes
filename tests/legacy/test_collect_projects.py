"""
Tests for Code/collect_projects.py

Covers:
- convert_runtime: time conversion calculation
- find_unavailable_urls: HTTP availability checking (mocked)
"""

from unittest.mock import MagicMock, patch

import pytest

from collect_projects import convert_runtime, find_unavailable_urls


# ---------------------------------------------------------------------------
# convert_runtime
# ---------------------------------------------------------------------------

class TestConvertRuntime:
    def test_zero_runtime(self):
        h, m, s = convert_runtime(0, 0)
        assert h == 0 and m == 0 and s == 0

    def test_one_hour(self):
        h, m, s = convert_runtime(0, 3600)
        assert h == 1 and m == 0 and s == 0

    def test_one_minute(self):
        h, m, s = convert_runtime(0, 60)
        assert h == 0 and m == 1 and s == 0

    def test_one_second(self):
        h, m, s = convert_runtime(0, 1)
        assert h == 0 and m == 0 and s == 1

    def test_mixed_duration(self):
        h, m, s = convert_runtime(0, 3661)  # 1h 1m 1s
        assert h == 1 and m == 1 and s == 1

    def test_non_zero_start(self):
        h, m, s = convert_runtime(100, 3760)  # 3660 s elapsed = 1h 1m 0s
        assert h == 1 and m == 1 and s == 0

    def test_48_hours(self):
        h, m, s = convert_runtime(0, 48 * 3600)
        assert h == 48 and m == 0 and s == 0

    def test_fractional_seconds_rounded(self):
        h, m, s = convert_runtime(0, 1.7)
        assert s == round(1.7)

    def test_returns_ints(self):
        h, m, s = convert_runtime(0, 3661)
        assert isinstance(h, int)
        assert isinstance(m, int)


# ---------------------------------------------------------------------------
# find_unavailable_urls
# ---------------------------------------------------------------------------

def _mock_response(status_code, is_redirect=False, location=None):
    r = MagicMock()
    r.status_code = status_code
    r.is_redirect = is_redirect
    r.headers = {"location": location} if location else {}
    return r


class TestFindUnavailableUrls:
    def test_empty_list(self):
        assert find_unavailable_urls([]) == []

    @patch("collect_projects.requests.head")
    def test_available_url_not_returned(self, mock_head):
        mock_head.return_value = _mock_response(200)
        result = find_unavailable_urls(["https://github.com/foo/bar"])
        assert result == []

    @patch("collect_projects.requests.head")
    def test_404_returned_as_unavailable(self, mock_head):
        mock_head.return_value = _mock_response(404)
        result = find_unavailable_urls(["https://github.com/private/repo"])
        assert "https://github.com/private/repo" in result

    @patch("collect_projects.requests.head")
    def test_403_returned_as_unavailable(self, mock_head):
        mock_head.return_value = _mock_response(403)
        result = find_unavailable_urls(["https://github.com/forbidden/repo"])
        assert len(result) == 1

    @patch("collect_projects.requests.head")
    def test_gitlab_login_redirect_unavailable(self, mock_head):
        mock_head.return_value = _mock_response(
            302, is_redirect=True,
            location="https://gitlab.com/users/sign_in"
        )
        result = find_unavailable_urls(["https://gitlab.com/private/repo"])
        assert "https://gitlab.com/private/repo" in result

    @patch("collect_projects.requests.head")
    def test_non_login_redirect_available(self, mock_head):
        # A 301 redirect to a different repo (rename/transfer) — still accessible
        mock_head.return_value = _mock_response(
            301, is_redirect=True,
            location="https://github.com/new-owner/repo"
        )
        result = find_unavailable_urls(["https://github.com/old-owner/repo"])
        assert result == []

    @patch("collect_projects.requests.head")
    def test_mixed_available_and_unavailable(self, mock_head):
        def side_effect(url, **kwargs):
            # Use distinct strings that don't overlap ("gone" vs "ok")
            return _mock_response(404 if "gone" in url else 200)
        mock_head.side_effect = side_effect

        urls = [
            "https://github.com/ok/repo",
            "https://github.com/gone/repo",
        ]
        result = find_unavailable_urls(urls)
        assert len(result) == 1
        assert "gone" in result[0]

    @patch("collect_projects.requests.head")
    @patch("collect_projects.time.sleep")
    def test_429_retried_then_available(self, mock_sleep, mock_head):
        # First call returns 429, second returns 200
        mock_head.side_effect = [
            _mock_response(429),
            _mock_response(200),
        ]
        result = find_unavailable_urls(["https://github.com/ratelimited/repo"])
        assert result == []
        assert mock_sleep.called

    @pytest.mark.xfail(
        strict=True,
        reason="Original find_unavailable_urls() has no try/except around "
               "requests.head() — network exceptions propagate uncaught.",
    )
    @patch("collect_projects.requests.head")
    def test_network_exception_marks_unavailable(self, mock_head):
        import requests as req
        mock_head.side_effect = req.RequestException("Connection refused")
        result = find_unavailable_urls(["https://github.com/unreachable/repo"])
        assert len(result) == 1
