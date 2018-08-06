#!/usr/bin/env python
import os
from datetime import datetime
from flask import Flask, abort, request, jsonify, g, url_for, make_response, request
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import and_
from functools import wraps
from flask_cors import CORS, cross_origin

# initialization
app = Flask(__name__)
cors = CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Credentials', 'true')
  return response

# extensions
db = SQLAlchemy(app)

# models + tables
follows_table = db.Table('user_follows', db.Model.metadata,
    db.Column('subscriber_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('publisher_id', db.Integer, db.ForeignKey('users.id'), nullable=False)
)

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    body_text = db.Column(db.Text)

    author = db.relationship('User')

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'             : self.id,
           'body_text'      : self.body_text,
           'created_on'     : str(self.created_on),
           'author'         : self.author.serialize
       }

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    member_since = db.Column(db.DateTime, default=datetime.utcnow)
    hashed_pw = db.Column(db.String(200))

    follows = db.relationship(
        'User', lambda: follows_table,
        primaryjoin=lambda: User.id == follows_table.c.subscriber_id,
        secondaryjoin=lambda: User.id == follows_table.c.publisher_id,
        backref='followers'
    )

    posts = db.relationship('Post')

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'             : self.id,
           'username'       : self.username
       }

def hash_password(password):
    return pwd_context.encrypt(password)

def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)

def generate_auth_token(user_id, expiration=6000):
    s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
    return s.dumps({'id': user_id})

def verify_auth_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None    # valid token, but expired
    except BadSignature:
        return None    # invalid token
    user = User.query.get(data['id'])
    return user

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.method is 'OPTIONS' and not auth():
            return abort(401)
        return f(*args, **kwargs)
    return decorated_function

def auth():
    token = request.cookies.get('login_token')
    if not token:
        token = request.args.get('auth')
        if not token:
            return False
    user = verify_auth_token(token)
    if not user:
        return False
    g.user = user
    return True

@app.route('/api/posts', methods=['POST'])
@login_required
def new_post():
    body_text = request.json.get('body_text')
    author_id = g.user.id
    if body_text is None:
        abort(400)    # missing arguments
    if User.query.filter_by(id=author_id).first() is None:
        abort(400)    # user doesn't exist
    post = Post(body_text=body_text, author_id=author_id)
    db.session.add(post)
    db.session.commit()
    return (jsonify({'post': post.id}), 201)
  
@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
@login_required
def remove_post(post_id):
    post_id = id
    post = Post.query.filter_by(id=post_id).first();
    if post is None:
        abort(400) #post doesn't exists
    db.session.delete(post)
    db.session.commit()
    return (jsonify({'deleted': True}))

@app.route('/api/users/<int:id>/posts', methods=['GET'])
@login_required
def get_posts(id):
    posts = Post.query.filter(Post.author_id==id);
    return (jsonify({'posts': [i.serialize for i in posts ]}))

@app.route('/api/me', methods=['GET'])
@login_required
def get_me():
    user = g.user
    return (jsonify({'user': user.serialize}))


@app.route('/api/users')
@login_required
def get_all_users():
    users = User.query.all()
    return jsonify({
        'users': [i.serialize for i in users],
        'count': len(users)
    })

@app.route('/api/users/<int:id>')
@login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify(user.serialize)

@app.route('/api/follows', methods=['POST'])
@login_required
def follow():
    id = g.user.id
    publisher_id=request.json.get('publisher_id')
    subscriber_id=id
    if publisher_id is None or publisher_id == subscriber_id:
        abort(400)
    statement = follows_table.insert().values(publisher_id=publisher_id, subscriber_id=subscriber_id)
    db.session.execute(statement)
    db.session.commit()
    return jsonify({'message': 'Follow successful.'})

@app.route('/api/follows', methods=['GET'])
@login_required
def get_follows():
    id = g.user.id
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'follows': [i.serialize for i in user.follows]})

@app.route('/api/followers', methods=['GET'])
@login_required
def get_followers():
    id = g.user.id
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'followers': [i.serialize for i in user.followers]})

@app.route('/api/follows/<int:publisher_id>', methods=['DELETE'])
@login_required
def stop_following(publisher_id):
    id = g.user.id
    statement = follows_table.delete().where(
        and_(follows_table.c.publisher_id==publisher_id, follows_table.c.subscriber_id==id))
    db.session.execute(statement)
    db.session.commit()
    return jsonify({'message': 'Unfollow successful.'})

@app.route('/api/feed', methods=['GET'])
@login_required
def get_feed():
    id = g.user.id
    user = User.query.get(id)
    if not user:
        abort(400)
    follow_ids = [i.id for i in user.follows]
    follow_ids.append(id)
    posts = Post.query.filter(Post.author_id.in_(follow_ids)).order_by(Post.created_on.desc()).all()
    return jsonify({'feed': [i.serialize for i in posts] })

@app.route('/api/login', methods=['POST'])
def app_login():
    username = request.json.get('username')
    password = request.json.get('password')
    # try to authenticate with username/password
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.hashed_pw):
        abort(401)
    token = generate_auth_token(user.id, 6000)
    resp = make_response(jsonify({'auth' : str(token)}))
    resp.set_cookie('login_token', token);
    return resp

@app.route('/api/logout')
@login_required
def app_logout():
    resp = make_response(jsonify({'success' : True}))
    resp.set_cookie('login_token', '', expires=0);
    return resp

@app.route('/api/register', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username, hashed_pw=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username, 'message': 'User created.'}), 201)


@app.route('/')
def inded():
    return jsonify({'message': 'It lives!'})

if __name__ == '__main__':
    db.create_all()
    app.run()
