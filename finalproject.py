from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Categories, Items, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catelog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Restaurant Information
@app.route('/categories/<int:categories_id>/Items/JSON')
def categoriesItemsJSON(categories_id):
    categories = session.query(Categories).filter_by(id=categories_id).one()
    Items = session.query(Items).filter_by(
        categories_id=categories_id).all()
    return jsonify(Items=[i.serialize for i in Items])


@app.route('/categories/<int:categories_id>/Items/<int:item_id>/JSON')
def menuItemJSON(categories_id, item_id):
    Items = session.query(Items).filter_by(id=item_id).one()
    return jsonify(Items=Items.serialize)


@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Categories).all()
    return jsonify(Categories=[c.serialize for c in Categories])

# Show all categories
@app.route('/')
@app.route('/categories/')
def showcategories():
    categories = session.query(Categories).order_by(asc(Categories.name))
    if 'username' not in login_session:
        return render_template('publicCategories.html', Categories=Categories)
    else:
        return render_template('categories.html', Categories=Categories)

# Create a new categories


@app.route('/categories/new/', methods=['GET', 'POST'])
def newcategories():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newcategories = Categories(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newcategories)
        flash('New categorie %s Successfully Created' % newcategories.name)
        session.commit()
        return redirect(url_for('categories.html'))
    else:
        return render_template('newcategories.html')

# Edit a categories


@app.route('/categories/<int:rcategories_id>/edit/', methods=['GET', 'POST'])
def editcategories(Categories_id):
    editedcategories = session.query(
        Categories).filter_by(id=categories_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedcategories.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this categories. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedcategories.name = request.form['name']
            flash('categories Successfully Edited %s' % editedcategories.name)
            return redirect(url_for('categories.html'))
    else:
        return render_template('editcategories.html', Categories=editedcategories)


# Delete a categories
@app.route('/categories/<int:categories_id>/delete/', methods=['GET', 'POST'])
def deletecategories(categories_id):
    categoriesToDelete = session.query(
        Categories).filter_by(id=categories_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if categoriesToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this categories. Please create your own categories in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(categoriesToDelete)
        flash('%s Successfully Deleted' % categoriesToDelete.name)
        session.commit()
        return redirect(url_for('categories.html', categories_id=categories_id))
    else:
        return render_template('deletecategories.html', Categories=categoriesToDelete)

# Show a categories Item


@app.route('/categories/<int:categories_id>/')
@app.route('/categories/<int:categories_id>/Items/')
def showItems(categories_id):
    categories = session.query(Categories).filter_by(id=categories_id).one()
    creator = getUserInfo(categories.user_id)
    Items = session.query(Items).filter_by(
        categories_id=categories_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicItems.html', Items=Items, categories=categories, creator=creator)
    else:
        return render_template('Items.html', Items=Items, categories=categories, creator=creator)


# Create a new item
@app.route('/categories/<int:categories_id>/Items/new/', methods=['GET', 'POST'])
def newItems(Categories_id):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Categories).filter_by(id=categories_id).one()
    if login_session['user_id'] != categories.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add menu items to this categorie. Please create your own categorie in order to add items.');}</script><body onload='myFunction()'>"
        if request.method == 'POST':
            newItem = Items(name=request.form['name'], description=request.form['description'],
            categories_id=categories_id, user_id=categories.user_id)
            session.add(newItems)
            session.commit()
            flash('New Item %s Successfully Created' % (newItem.name))
            return redirect(url_for('Items.html', categories=categories_id))
    else:
        return render_template('newitems.html', categories_id=categories_id)

# Edit a item


@app.route('/categories/<int:categories_id>/Items/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(categories_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Items).filter_by(id=item_id).one()
    categories = session.query(Categories).filter_by(id=categories_id).one()
    if login_session['user_id'] != categories.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit  items to this categorie. Please create your own categorie in order to edit items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('categorie Item Successfully Edited')
        return redirect(url_for('Items.html', categories_id=categories_id))
    else:
        return render_template('editItems.html', categories_id=categories_id, item_id=item_id, Items=editedItem)


# Delete a item
@app.route('/categories/<int:categories_id>/Items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(categories_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Categories).filter_by(id=categories_id).one()
    ItemsToDelete = session.query(Items).filter_by(id=item_id).one()
    if login_session['user_id'] != categories.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete items to this categorie. Please create your own categories in order to delete items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(ItemsToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('Items.html', categories_id=categories_id))
    else:
        return render_template('deleteItems.html', item=ItemsToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showcategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showcategories'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=9000)
