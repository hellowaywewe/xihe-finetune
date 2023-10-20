#!/usr/bin/env python
import os
import time
import logging

from flask import Flask, abort, request, jsonify, g, url_for, make_response
from flask_httpauth import HTTPTokenAuth
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String
from flask_cors import *
from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError
from werkzeug.security import generate_password_hash, check_password_hash

from .fmh import FoundationModelHandler, BASIC_CONFIG


app = Flask(__name__)
fmh = FoundationModelHandler()

CORS(app, supports_credentials=True)

# initialization
# todo: put the secret key to KMC & use a HASH KEY
basic_config = BASIC_CONFIG
app.config["SECRET_KEY"] = basic_config['SECRET_KEY']
app.config["SQLALCHEMY_DATABASE_URI"] = basic_config['FINETUNE_MYSQL_URI']
app.config["SQLALCHEMY_COMMIT_ON_TEARDOWN"] = True
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True

gunicorn_logger = logging.getLogger("gunicorn.error")
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

auth = HTTPTokenAuth(scheme="JWT")

if not os.path.exists(basic_config['CA_CERT_PATH']):
    raise FileExistsError("Cert file does not exist.")

engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'],
                       max_overflow=0,
                       pool_size=5)
conn = engine.connect()
Session = sessionmaker(bind=conn)
session = scoped_session(Session)
os.remove(basic_config['CA_CERT_PATH'])

# 执行declarative_base获得一个类
Base = declarative_base()

class User(Base):
    __tablename__ = basic_config['FINETUNE_TABLE']
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, duration=60):
        # 设置 JWT 头部信息
        header = {"alg": "HS256"}
        # 设置 JWT 负载信息
        expiration = int(time.time()) + duration
        payload = {
            "sub": self.id,
            "name": self.username,
            "exp": expiration
        }
        # 生成JWT
        token = jwt.encode(header, payload, app.config["SECRET_KEY"])
        return jsonify({"token": token.decode("utf-8")})

    @staticmethod
    def verify_auth_token(token):
        try:
            # 验证并解码 JWT
            claims = jwt.decode(token, app.config["SECRET_KEY"])
            # 获取当前用户信息
            user = session.query(User).get(claims["sub"])
        except ExpiredTokenError:
            app.logger.info("token invalid")
            return None
        except Exception:
            return None
        return user


@auth.verify_token
def verify_token(token):
    # Config.SECRET_KEY:内部的私钥，这里写在配置信息里
    user = User.verify_auth_token(token)
    if not user:
        return False
    g.user = user
    return True


# 公共返回值
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({"error": "Not found"}), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({"error": "Bad Request"}), 400)


@app.route("/health", methods=["GET"])
def health_func():
    return jsonify({"health": "true"})


@app.route("/foundation-model/users", methods=["POST"])
def new_user():
    if request.json is None:
        abort(400)
    username = request.json.get("username")
    password = request.json.get("password")
    if username is None or password is None:
        abort(400)  # missing arguments
    if session.query(User).filter(User.username==username).first() is not None:
        return jsonify({"status": "-1", "msg": "用户名已存在"})  # existing user
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return (jsonify({"username": user.username}), 201, {
        "Location": url_for("get_user", id=user.id, _external=True)
    })


@app.route("/foundation-model/users/<int:id>")
def get_user(id):
    user = session.query(User).get(id)
    if not user:
        abort(400)
    return jsonify({"username": user.username})


@app.route("/foundation-model/token", methods=["POST"])
def get_auth_token():
    if request.json is None:
        abort(400)
    username = request.json.get("username")
    password = request.json.get("password")
    if username is None or password is None:
        abort(400)  # missing arguments
    user = session.query(User).filter_by(User.username==username).first()
    if not user or not user.verify_password(password):
        return jsonify({"status": "-1", "msg": "用户名不存在或者用户名错误或者密码错误"})
    g.user = user
    duration = 600
    token = g.user.generate_auth_token(duration)
    return jsonify({
        "status": 200,
        "msg": "获取token成功",
        "token": token.json["token"],
        "duration": duration
    })


@app.route("/v1/foundation-model/finetune", methods=["POST"])
@auth.login_required
def create_finetune():
    app.logger.info(f"create: {request.json}")
    if not request.json:
        abort(400)
    for key in ["user", "task_name", "foundation_model", "task_type"]:
        if key not in request.json and not isinstance(request.json[key], str):
            abort(400)
    data = request.json
    user = data.get("user")
    task_name = data.get("task_name")
    foundation_model = data.get("foundation_model")
    task_type = data.get("task_type")
    parameters = data.get("parameters", None)
    params = {}
    # name value
    #  "parameters": [{"name": "epochs", "value": "2"}, {"name": "start_learning_rate", "value": "0.001"}, {"name": "end_learning_rate", "value": "0.00001"}]
    if parameters:
        for param in parameters:
            params[param["name"]] = param["value"]
    app.logger.info(f"params: {params}")
    res = fmh.create_finetune_by_user(user=user,
                                      task_name=task_name,
                                      foundation_model=foundation_model,
                                      task_type=task_type,
                                      **params)
    app.logger.info(f"res: {res}")
    if res == -1:
        return jsonify({"status": -1, "msg": "创建微调任务失败"}), 201
    return jsonify({"status": 201, "msg": "创建微调任务成功", "job_id": res}), 201


@app.route("/v1/foundation-model/finetune/<string:job_id>", methods=["GET"])
@auth.login_required
def get_finetune(job_id):
    app.logger.info(f"get: {job_id}")
    res = fmh.get_finetune_info(job_id)
    app.logger.info(f"res: {res}")
    if not res:
        return jsonify({"status": -1, "msg": "查询微调详情失败"}), 200
    return jsonify({"status": 200, "msg": "查询微调详情成功", "data": res})


@app.route("/v1/foundation-model/finetune/<string:job_id>", methods=["PUT"])
@auth.login_required
def terminal_finetune(job_id):
    app.logger.info(f"terminal: {job_id}", job_id)
    res = fmh.terminal_finetune(job_id)
    app.logger.info(f"res: {res}")
    if res is False:
        return jsonify({"status": -1, "msg": "终止微调任务失败"}), 200
    return jsonify({"status": 202, "msg": "终止微调任务成功"}), 200


@app.route("/v1/foundation-model/finetune/<string:job_id>", methods=["DELETE"])
@auth.login_required
def delete_finetune(job_id):
    app.logger.info(f"delete: {job_id}")
    res = fmh.delete_finetune(job_id)
    app.logger.info(f"res: {res}")
    if res is False:
        return jsonify({"status": -1, "msg": "删除微调任务失败"}), 200
    return jsonify({"status": 204, "msg": "删除微调任务成功"}), 200

@app.route("/v1/foundation-model/finetune/<string:job_id>/log/",
           methods=["GET"])
@auth.login_required
def get_log(job_id):
    app.logger.info(f"get log: {job_id}")
    res = fmh.get_finetune_log_url(job_id=job_id)
    app.logger.info(f"res: {res}")
    if not res:
        return jsonify({
            "status": -1,
            "msg": "查询微调日志失败, 还未生成日志或者job_id不存在"
        }), 200
    return jsonify({
        "status": 200,
        "msg": "查询微调日志成功",
        "obs_url": res["obs_url"]
    })


