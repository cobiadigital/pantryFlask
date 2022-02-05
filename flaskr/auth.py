import functools
from flask import(
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
import pytz
from pytz import timezone
#from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import abort
from flaskr.db import get_db
bp = Blueprint('auth', __name__, url_prefix='/')

central = timezone('US/Central')

@bp.route('/', methods=('GET', 'POST'))
def index():
    if request.method == 'POST':
        phonenumber = request.form['phonenumber']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE phonenumber = ?', (phonenumber,)
        ).fetchone()

        if user is None:
            return redirect(url_for('auth.register', phonenumber=phonenumber) )
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            id = user['id']
            if user['check_in_state'] == 0:
                db.execute(
                    "UPDATE user SET check_in_state = ?, last_check_in = current_timestamp WHERE ID = ?",
                    (1, id),
                    )
                db.execute(
                    'INSERT INTO time_sheet (user_id, check_in_state) VALUES (?, ?)',
                    (id, 1),
                )
                db.commit()
            return redirect(url_for('index'))
        flash(error)
    return render_template('auth/index.html')

@bp.route('/register', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        phonenumber = request.form['phonenumber']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']

        db = get_db()
        error = None

        if not phonenumber:
            error = 'Phonenumber is required.'
        elif not firstname:
            error = 'Your name is required.'
        elif not lastname:
            error = 'Your name is required.'
        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (phonenumber, firstname, lastname, email, check_in_state) VALUES (?, ?, ?, ?, ?)",
                    (phonenumber, firstname, lastname, email, 1),
                    )
                db.commit()
            except db.IntegrityError:
                error = f"The Phone Number: {phonenumber} is already registered."
            else:
                user = db.execute(
                    'SELECT * FROM user WHERE phonenumber = ?', (phonenumber,)
                ).fetchone()
                session['user_id'] = user['id']
                id = user['id']
                return redirect(url_for("index"))
        flash(error)
    return render_template('auth/register.html')

@bp.route('/update', methods=('GET', 'POST'))
def update():
    user = g.user

    if request.method == 'POST':
        id = g.user['id']
        phonenumber = request.form['phonenumber']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        db = get_db()

        error = None
        if not phonenumber:
            error = 'Phonenumber is required.'
        elif not firstname:
            error = 'Your name is required.'
        elif not lastname:
            error = 'Your name is required.'
        elif error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE user SET phonenumber = ?, firstname = ?, lastname = ?, email = ?'
                ' WHERE id = ?',
                (phonenumber, firstname, lastname, email, id)
            )
            db.commit()
            return redirect(url_for('auth.index'))

    return render_template('auth/update.html', post=user)


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped_view

@bp.route('/checkout', methods=('GET', 'POST'))
def checkout():
    if request.method == 'POST':
        checkout = request.form['checkout']
        id = g.user['id']
        db = get_db()
        db.execute(
            "UPDATE user SET check_in_state = ?, last_check_out = current_timestamp WHERE ID = ?",
            (checkout,  id),
        )
        db.execute(
            "INSERT INTO time_sheet (user_id, check_in_state) VALUES (?, ?)",
            (id, checkout),
        )
        db.commit()
        return redirect(url_for('auth.checkout'))
    return render_template('auth/checkout.html')

def update_time():
    if request.method == 'POST':
        db = get_db()
        db.execute(
            "UPDATE user SET check_in_state = ?, last_check_out = current_timestamp WHERE ID = ?",
            (checkout,  id),
        )
        db.execute(
            "INSERT INTO time_sheet (user_id, check_in_state) VALUES (?, ?)",
            (id, checkout),
        )
        db.commit()
        return redirect(url_for('auth.checkout'))
    return render_template('auth/checkout.html')



