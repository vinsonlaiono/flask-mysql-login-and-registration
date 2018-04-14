from flask import Flask, render_template, redirect, request, session, flash
# import the function connectToMySQL from the file mysqlconnection.py
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = 'durantula'
bcrypt = Bcrypt(app)
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# invoke the connectToMySQL function and pass it the name of the database we're using
# connectToMySQL returns an instance of MySQLConnection, which we will store in the variable 'mysql'
mysql = connectToMySQL('login_registration')
# now, we may invoke the query_db method
# print("all the users", mysql.query_db("SELECT * FROM users;"))

# ROOT ROUTE
@app.route('/')
def index():
  
    return render_template('index.html')
@app.route('/results')
def results():
    # CHECKS IF THERE IS A USER IS IN SESSION
    if 'userid' in session:
        id = session['userid']
        # QUERIES FOR THE USER ID IN SESSION
        namequery = "SELECT first_name FROM users WHERE id = %(id)s"
        data = {'id':id}
        username = mysql.query_db(namequery, data)

        # query for all messages from all users and when is was said
        message_query = "SELECT * FROM messages JOIN users on users.id = messages.user_id"
        messagenger = mysql.query_db(message_query)
        # print(messagenger)
        
        comment_query = "SELECT * FROM comments JOIN users on users.id = comments.user_id"
        commenter = mysql.query_db(comment_query)
        print('comments')
        print(commenter)
        
        return render_template('results.html', name = username, messages = messagenger, comments = commenter)
    else:
        flash("You are not logged in.")
        return redirect('/')

#-------------------------------------------------
#        GET MESSAGES AND COMMENTS
#------------------------------------------------- 
@app.route('/message', methods=['POST'])
def message_post():
    message = request.form['wallmessage']
    if len(message) < 1:
        flash(f'Message box cannot be empty', 'message_box')
        return redirect('/results')

    print(message)
    id = session['userid']
    # QUERY TO GET ALL MESSAGES FROM DB
    query = "INSERT INTO messages(message, updated_at, created_at, user_id) VALUES(%(message)s, now(), now(), %(id)s)"
    data = {'message': message, 'id':id}
    new_message = mysql.query_db(query,data)

    return redirect('/results')

@app.route('/comment', methods=['POST'])
def comment_post():  

    comment = request.form['user_comment_box']
    message_id = request.form['message_id']
    id = session['userid']
    if len(comment) < 1:
        flash(f'Comment box cannot be empty', 'message_box')
        return redirect('/results')
    
    query = "INSERT INTO comments(comment, updated_at, created_at, message_id, user_id) VALUES(%(comment)s, now(), now(), %(message_id)s, %(id)s)"
    data = {'comment': comment, 'message_id': message_id, 'id':id}
    new_message = mysql.query_db(query,data)

    return redirect('/results')
#--------------------------------------------------
#               REGISTRATION
#--------------------------------------------------
@app.route('/registration', methods=['POST'])
def registration():
    
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # FIRST NAME VALIDATION
    # CHECK IF FIRST NAME FIELD IS EMPTY
    if len(first_name) < 1:
        flash(f'First name cannot be empty', 'registration_error')
        return redirect('/')
    if len(first_name) < 2:
        flash(f'Name must contain at least 2 characters', 'registration_error')
        return redirect('/')
    # CHECK IF NAME CONTAINS A NUMBER
    def num_there(s):
        return any(i.isdigit() for i in s)
    if num_there(first_name) == True:
        flash(f'First name cannot contain numbers')
        #---------------------LAST NAME VALIDATION--------------------
    # CHECK IF LAST NAME FIELD IS EMPTY
    if len(last_name) < 1:
        flash(f'Last name cannot be empty')
        return redirect('/')
    # CHECK IF NAME IS AT LEAST 2 CHARACTERS
    if len(last_name) < 2:
        flash(f'Name must contain at least 2 characters')
        return redirect('/')
    # CHECK IF LAST CONTAINS A NUMBER
    def num_there(s):
        return any(i.isdigit() for i in s)
    if num_there(last_name) == True:
        flash(f'Last name cannot contain numbers')
    #---------------------EMAIL VALIDATION-----------------------------
    # CHECK IF EMAIL IF VALID
    if len(email) < 1:
        flash("Email cannot be blank!")
        return redirect('/')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
        return redirect('/')
    # check is email is aleady in the database-------------------------
    check = "SELECT email FROM users WHERE email = %(email)s"
    email_stuff =  {'email': email}
    email_check = mysql.query_db(check, email_stuff)
    if email_check:
        flash("Email already exits!")
        return redirect('/')
    #-----------------------PASSWORD VALIDATION-----------------------
    #CHECK IF IS VALID AND MATCHING
    if password != confirm_password:
        flash(f"Passwords do not match")
        return redirect('/')
    if len(password) < 8:
        flash(f"Password must contain at least 8 characters")
        return redirect('/')
    # CHECKS IF PASSWORD HAS AT LEAST 1 CHARACTER
    if not re.search(r"[\d]+", password):
        flash(f"Password must contain at least 1 numeric value")
        return redirect('/')
    # CHECKS FOR PASSWORD 1 UPPERCASE CHARACTER
    if not re.search(r"[\d]+", password):
        flash(f"Password must contain at least 1 uppercase character")
        return redirect('/')
    if not re.search(r"[A-Z]+", password):
        flash(f"Password must contain at least 1 uppercase character")
        return redirect('/')
    # BCRYPT HASH
    # pw_hash = bcrypt.generate_password_hash(password)
    
    # query to insert the values from the form into the database
    query = "INSERT INTO users (first_name, last_name, email, password, updated_at, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
    data = {
             'first_name': request.form['first_name'],
             'last_name':  request.form['last_name'],
             'email': request.form['email'],
             'password': password
           }
    mysql.query_db(query, data)
    # query for the id of the user that just registered using email of request.form
    newquery = "SELECT id FROM users WHERE email = %(email)s"
    newdata = {'email':email}
    check = mysql.query_db(newquery, newdata)
    print(check)    
    # CHECKING IF THE EMAIL QUERY RETURNS THE NEW USERS ID WHERE ID'S MATCH
    if check:
        session['userid'] = check[0]['id']
        return redirect('/results')
#--------------------------------------------------
#                       LOGIN
#--------------------------------------------------
@app.route('/login', methods=['POST'])  
def login():
    session['init'] = 0
    email = request.form['login_email']
    password = request.form['password']

    #---------------------EMAIL VALIDATION---------------------
    # check is email is aleady in the database
    check = "SELECT id, first_name, email, password FROM users WHERE email = %(email)s AND password = %(password)s"
    email_stuff =  {
        'email': email,
        'password':password
    }
    login = mysql.query_db(check, email_stuff)
    # checks for the email and password match in the data base
    if login:
        session['userid'] = login[0]['id'] 
        return redirect('/results')
    else:
        flash('Failed to log in')
        return redirect('/')
#--------------------------------------------------
#                     LOGOUT
#--------------------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":  
    app.run(debug=True)