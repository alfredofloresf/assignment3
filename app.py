from flask import Flask, render_template, redirect, url_for, make_response, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, validators
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from subprocess import check_output

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/appsec/PycharmProjects/Part2/database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



def validate_phone(form, field):

    if len(field.data) > 14:
        raise ValidationError('Failure: This is an invalid phone number, too many characters')
    else:
        sanitized_phone_number = field.data.strip(' ()-')
        if len(sanitized_phone_number) == 10 or len(sanitized_phone_number) == 11:
            for i in range(len(sanitized_phone_number)):
                if sanitized_phone_number[i].isnumeric():
                    continue
                else:
                    raise ValidationError('Failure: Phone numbers must only contain numbers')
        else:
            raise ValidationError('Failure: Phone numbers must contain 10 digits (or 11 with country code)')




class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    twofa = db.Column(db.String(50))
    password = db.Column(db.String(80))



class SpellForm(FlaskForm):
    inputtext = StringField('CheckText', id='inputtext', validators=[InputRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', id='uname', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', id='pword', validators=[InputRequired(), Length(min=4, max=20)])
    # twofa = StringField('2fa', id='2fa', validators=[InputRequired(), Length(max=50)])
    twofa = StringField('two_fa', id='2fa', validators=[validate_phone, validators.Optional()])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    username = StringField('Username', id='uname', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', id='pword', validators=[InputRequired(), Length(min=4, max=20)])
    # twofa = StringField('2fa', id='2fa', validators=[InputRequired(), Length(max=50)])
    twofa = StringField('two_fa', id='2fa', validators=[validate_phone, validators.Optional()])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Failure: Username is already in use')



    #twofa = StringField('2fa', id = '2fa', validators=[validate_phone, validators.Optional()])





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    result = None
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                result = "success"
                return render_template('login.html', form=form, result=result)
        #result = "incorrect"
        #return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.uname.data + ' ' + form.pword.data + '</h1>'

    return render_template('login.html', form=form, result=result)


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellForm()
    return render_template('spell_check.html', form=form)
    textout = None
    misspelled = None
    if request.method == 'POST':
        inputtext = form.inputtext.data
        textout = inputtext
        with open ("words.txt", "w") as fo:
            fo.write(inputtext)
        output = (check_output(["./a.out", "words.txt", "wordlist.txt"], universal_newlines=True))
        misspelled = output.replace("\n",",").strip().strip(',')
    response = make_response(render_template('spell_check.html', form=form, textout=textout, misspelledd=misspelled))
    response.headers['Content-Security-Policy'] = "default-scr 'self'"
    return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, twofa=form.twofa.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1 id="success">success</h1>'
    return render_template('register.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)