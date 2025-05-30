from flask import Flask, request, Response, abort, render_template
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

from collections import defaultdict

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'loginexample'


class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


users = {
    1: User(1, 'peinan', 'peinan'),
    2: User(2, 'user', 'user')
}

nested_dict = lambda: defaultdict(nested_dict)
user_check = nested_dict()
for i in users.values():
    user_check[i.username]['password'] = i.password
    user_check[i.username]['id'] = i.id


@login_manager.user_loader
def load_user(id):
    return users.get(int(id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', None)
        password = request.form.get('password', None)
        if username in user_check and password == user_check[username]['password']:
            id = user_check[username]['id']
            login_user(users.get(id))

            return f'login success: {current_user.username}'
        else:
            return abort(401)
    else:
        return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return Response('logout sucess.<br/><a href="/login">login</a>')


@app.route('/')
@login_required
def home():
    return Response(f"{current_user.username}: <a href='/logout'>Logout</a>")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)