#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Flaskr
    ~~~~~~

    A microblog example application written as Flask tutorial with
    Flask and sqlite3.

    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import os

ALLDIRS = ['/afs/andrew.cmu.edu/usr4/worichte/flask_env/lib/python2.6/site-packages']

import sys
import site

# Remember original sys.path.
prev_sys_path = list(sys.path)

# Add each new site-packages directory.
for directory in ALLDIRS:
    site.addsitedir(directory)

# Reorder sys.path so new directories at the front.
new_sys_path = []
for item in list(sys.path):
    if item not in prev_sys_path:
        new_sys_path.append(item)
        sys.path.remove(item)
        sys.path[:0] = new_sys_path

import flask
from sqlite3 import dbapi2 as sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
import wsgi_wrapper as cgi_wrap

# print "starting Flaskr"

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE= '/tmp/flaskr.db',
    DEBUG=True,
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)


def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


# @app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/')
def show_entries():
    db = get_db()
    cur = db.execute('select title, text from entries order by id desc')
    entries = cur.fetchall()
    return render_template('show_entries.html', entries=entries)


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    db.execute('insert into entries (title, text) values (?, ?)',
               [request.form['title'], request.form['text']])
    db.commit()
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('show_entries'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))

if __name__ == '__main__':
    cgi_wrap.run_with_cgi(app)
