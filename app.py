from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from scanner import scan_sql_injection, scan_xss, scan_open_redirect

app = Flask(__name__)
app.secret_key = 'replace_this_with_a_random_secret_key'
csrf = CSRFProtect(app)

class ScanForm(FlaskForm):
    url = StringField('Target URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Scan')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = ScanForm()
    result = None
    owasp_checklist = [
        'Injection',
        'Broken Authentication',
        'Sensitive Data Exposure',
        'XML External Entities (XXE)',
        'Broken Access Control',
        'Security Misconfiguration',
        'Cross-Site Scripting (XSS)',
        'Insecure Deserialization',
        'Using Components with Known Vulnerabilities',
        'Insufficient Logging & Monitoring'
    ]
    logs = []
    if form.validate_on_submit():
        url = form.url.data
        from io import StringIO
        import sys
        output = StringIO()
        sys_stdout = sys.stdout
        sys.stdout = output
        scan_sql_injection(url, logs)
        scan_xss(url, logs)
        scan_open_redirect(url, logs)
        sys.stdout = sys_stdout
        result = output.getvalue()
    return render_template('index.html', form=form, result=result, owasp_checklist=owasp_checklist, logs=logs)
    return render_template('index.html', form=form, result=result, owasp_checklist=owasp_checklist)

if __name__ == '__main__':
    app.run(debug=True)
