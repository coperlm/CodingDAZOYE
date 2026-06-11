import flask
import subprocess


app = flask.Flask(__name__)


@app.route("/route_param/<route_param>")
def route_param(route_param):
    subprocess.call("grep -R {} .".format(route_param), shell=True, cwd="/tmp")
    return "oops!"