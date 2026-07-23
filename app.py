import flask
import flask_cors

app = flask.Flask("Crisis-Mosaic")
flask_cors.CORS(app)

@app.route("/")

def index():
    return """<html>
<head>
<title>Crisis Mosaic</title>
</head>
<body>
<h1>Crisis Mosaic</h1>
<bottom><a href="https://www.bilibili.com/video/BV1Y829BsEfC/">??????????</a></bottom>
</body>
</html>"""

if __name__ == "__main__":
    app.run(debug=True)
