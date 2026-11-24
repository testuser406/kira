"""Import this module in a script to make `urllib.request.urlopen` sign in automatically.

Set KIRA_USER and KIRA_PASSWORD; on the first 401 from a Kira API URL the helper logs in
(cookie kept in-process) and retries the request once. Without credentials it does nothing.
"""
import http.cookiejar
import json
import os
import urllib.error
import urllib.parse
import urllib.request

_user, _password = os.environ.get("KIRA_USER"), os.environ.get("KIRA_PASSWORD")
if _user and _password:
    _jar = http.cookiejar.CookieJar()
    _opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_jar))
    _logged_in: set[str] = set()

    def _origin(target) -> str:
        url = target.full_url if isinstance(target, urllib.request.Request) else target
        parts = urllib.parse.urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    def _login(origin: str) -> None:
        body = json.dumps({"username": _user, "password": _password}).encode()
        req = urllib.request.Request(origin + "/api/v1/auth/login", data=body, headers={"Content-Type": "application/json"})
        _opener.open(req, timeout=15).read()
        _logged_in.add(origin)

    def urlopen(target, data=None, timeout=15, **kwargs):
        origin = _origin(target)
        if origin not in _logged_in:
            try:
                return _opener.open(target, data, timeout)
            except urllib.error.HTTPError as err:
                if err.code != 401:
                    raise
                _login(origin)
        return _opener.open(target, data, timeout)

    urllib.request.urlopen = urlopen
