"""Public website support form. Only the official website origin is permitted."""
import os, re, time, threading
from html import escape
from fastapi import Request
from fastapi.responses import JSONResponse
from sm360_email import send_email, configured

ALLOWED = {'https://signmaster360.co.za', 'https://www.signmaster360.co.za'}
TOPICS = {'Account and login','Subscription and billing','Jobs and production','Technical assistance','General enquiry'}
_lock = threading.Lock()
_recent = {}

def setup(app):
    @app.api_route('/api/public/support', methods=['OPTIONS', 'POST'])
    async def public_support(request: Request):
        origin = request.headers.get('origin', '')
        headers = {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600'} if origin in ALLOWED else {}
        if origin not in ALLOWED:
            return JSONResponse({'ok': False, 'error': 'Origin not allowed'}, status_code=403)
        if request.method == 'OPTIONS':
            return JSONResponse({}, headers=headers)
        if not configured():
            return JSONResponse({'ok': False, 'error': 'Support email is temporarily unavailable'}, status_code=503, headers=headers)
        if int(request.headers.get('content-length', '0') or 0) > 12000:
            return JSONResponse({'ok': False, 'error': 'Message too large'}, status_code=413, headers=headers)
        try:
            payload = await request.json()
            if not isinstance(payload, dict): raise ValueError()
            name = str(payload.get('name','')).strip()
            email = str(payload.get('email','')).strip()
            phone = str(payload.get('phone','')).strip()
            subject = str(payload.get('topic','')).strip()
            message = str(payload.get('message','')).strip()
            honey = str(payload.get('_honey','')).strip()
            if honey: return JSONResponse({'ok': True}, headers=headers)
            if not (1 <= len(name) <= 120 and 5 <= len(email) <= 254 and re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) and len(phone) <= 40 and subject in TOPICS and 1 <= len(message) <= 5000):
                raise ValueError()
        except (ValueError, TypeError):
            return JSONResponse({'ok': False, 'error': 'Please check the form fields'}, status_code=422, headers=headers)
        ip = request.client.host if request.client else 'unknown'
        now = time.monotonic()
        with _lock:
            for k in list(_recent):
                _recent[k] = [t for t in _recent[k] if now-t < 3600]
                if not _recent[k]: del _recent[k]
            timestamps = _recent.setdefault(ip, [])
            if len(timestamps) >= 5:
                return JSONResponse({'ok': False, 'error': 'Too many requests. Please try again later.'}, status_code=429, headers=headers)
            timestamps.append(now)
        content = '<h2>SignMaster 360 website support request</h2>' + ''.join('<p><b>'+escape(k)+':</b> '+escape(v).replace('\n','<br>')+'</p>' for k,v in [('Name',name),('Email',email),('Phone',phone),('Topic',subject),('Message',message)])
        try:
            send_email('support@signmaster360.co.za', 'Website support: ' + subject, content)
        except Exception:
            return JSONResponse({'ok': False, 'error': 'Unable to send right now. Please try again later.'}, status_code=502, headers=headers)
        return JSONResponse({'ok': True, 'message': 'Your support request has been sent successfully.'}, headers=headers)
