from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')  # Vulnerable to XSS
    return f"Search result: {query}"

@app.route('/admin')
def admin():
    return "Admin Dashboard"  # Vulnerable to Broken Access Control

@app.route('/db')
def db():
    query = request.args.get('id')  # Vulnerable to SQLi (mock)
    return f"SQL error: {query}"  # Simulates SQLi response

if __name__ == '__main__':
    app.run(port=5001)