
import shutil
import zipfile
import io
import pickle
import base64
import logging
import smtplib
import random
import os
import gc
import re
import pandas as pd
import secrets
import traceback
import psycopg2
from werkzeug.utils import secure_filename
from flask import Flask, request, flash, redirect, send_file, render_template, url_for, jsonify, session
from exception import DataNotAvailable
import redis
import base64
from flask_session import Session
from flask import session
from sqlalchemy import create_engine
from flask_sqlalchemy import SQLAlchemy
from exception import *
import time
import logging
log = logging.getLogger('werkzeug')
log.disabled = True

# Initialize logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
handler = logging.FileHandler('error.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

app = Flask(__name__, template_folder='templates')

# IMPORTANT: Keep a fixed secret key (not random on each restart)
# Set secret key
os.environ["FLASK_SECRET_KEY"] = "5e51c919613c4c039f841a94f2d2b514"

app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]


app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "flask_session_dispatch:"
app.config["SESSION_REDIS"] = redis.StrictRedis(host='128.91.51.73', port=6379, db=3, decode_responses=False)

# Initialize Flask-Sessionf
Session(app)

# Upload folder (base). Ensure it exists
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sql_connection():
    "Establish a PostgreSQL connection."

    connection_string = 'postgres://postgres:postgres@128.91.51.73:5432/dispatch_details'
    connection = psycopg2.connect(connection_string)
    return connection

def create_register_table(conn):
    try:
        sql_query = """ CREATE TABLE IF NOT EXISTS public.register_table_dispatch_details
                        (
                            user_id serial PRIMARY KEY,
                            username varchar NOT NULL UNIQUE,
                            password bytea NOT NULL,
                            email_id character varying(255) NOT NULL UNIQUE,
                            datetime timestamptz not null
                        )
                    """
        curr = conn.cursor()
        curr.execute(sql_query)
        return 0
    except:
        return 'Table Not Created.'
    

def create_register_table(conn):
    try:
        sql_query = """CREATE TABLE IF NOT EXISTS public.user_login
            (
                id serial Primary key ,
                email character varying(255) NOT NULL,
                login_time timestamp without time zone NOT NULL DEFAULT now()
            )
            """
        curr = conn.cursor()
        curr.execute(sql_query)
        return 0
    except:
        return 'Table Not Created.'

@app.route('/', methods=['GET', 'POST'])
def login_page():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']

            sql_query = f"select * from public.register_table_dispatch_details where email_id = '{email}';"
            connection = sql_connection()
            if connection == 'Connection Error':
                raise PgConnectionError()

            else:
                curr = connection.cursor()
                curr.execute(sql_query)
                rows  = curr.fetchall()
                connection.close()

            if  len(rows) == 0 :
                flash("Email Id Not Found.", "error")

            if len(rows) != 0 :
                if rows[0][3] != email :
                    flash("Invalid Email Id", "error")
                    return redirect(url_for('login_page'))

                decPassword = base64.b64decode(rows[0][2]).decode("utf-8")
                if password == decPassword:
                    session['email'] = email

                    sql_query = f"INSERT INTO User_login (email) VALUES ('{email}');"
                    connection = sql_connection()
                    if connection == 'Connection Error':
                        raise PgConnectionError()

                    else:
                        curr = connection.cursor()
                        curr.execute(sql_query)
                        connection.commit()
                        connection.close()
                    app.logger.debug(f"Session data: {session.items()}")
                    return redirect(url_for('index'))
                else:
                    flash("Invalid Password", "error")
                del [decPassword]
                gc.collect()
            del email,password,sql_query,rows
            gc.collect()
        return render_template('login.html')
    except PgConnectionError as exe:
        return jsonify({'error':str(exe)}),400



def send_mail(receiver_email_id,message):
    try:
        sender_email_id = 'mayurnandanwar@ghcl.co.in'
        password = 'uvhr zbmk yeal ujhv'
        # creates SMTP session
        s = smtplib.SMTP('smtp.gmail.com', 587)
        # start TLS for security
        s.starttls()
        # Authentication
        s.login(sender_email_id, password)
        # message to be sent
        # sending the mail
        s.sendmail(sender_email_id, receiver_email_id, str(message))
        # terminating the session
        s.quit()

        del sender_email_id,password
        gc.collect()
        return 0
    except:
        return jsonify({'error':'The Message cannot be Sent.'})


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            connection = sql_connection()
            table_create = create_register_table(connection)
            if table_create == 0:
                curr = connection.cursor()
                sql = f"SELECT email_id FROM public.register_table_dispatch_details WHERE email_id = '{email}';"

                curr.execute(sql)
                rows = curr.fetchall()
                connection.close()
            else:
                raise PgConnectionError()

            if len(rows) == 0:
                # Check if passwords match
                if password != confirm_password:
                    flash("Passwords do not match!", "error")
                    return redirect(url_for('signup'))

                # Check password strength using regex
                password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
                if not password_pattern.match(password):
                    flash("Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character.", "error")
                    return redirect(url_for('signup'))

                # Generate a random token
                token = random.randint(100000, 999999)

                # Store the token in the session for validation
                session['token'] = str(token)
                session['email'] = email
                app.logger.debug(f"Session data: {session.items()}")
                # this required for adding pass and name after validation
                session['password'] = password
                session['name'] = name
                # Send the token via email
                subject = "Email Verification Code"
                body = f"Your verification code is {token}. Please enter it on the website to verify your email."
                message = f"Subject: {subject}\n\n{body}"
                msg = send_mail(email, message)

                if msg == 0:
                    flash("Code has been sent to register email id.", "info")
                    # Redirect to the validate_mail route with email as a parameter
                    return redirect(url_for('validate_mail', email=email))
                del password_pattern,token,subject,body,message,msg
                gc.collect()
            else:
                flash("Email Already Exist.", "info")
        return render_template('signup.html')
    except PgConnectionError as exe:
        return jsonify({"error": str(exe)})



@app.route('/validate_mail',methods=['POST','GET'])
def validate_mail():

    try:
        email = request.args.get('email')  # Retrieve email from query string

        if request.method == 'POST':
            entered_token = str(request.form['token'])

            # Compare the entered token with the session token
            if str(session.get('token')) == str(entered_token):
                password = session['password']
                name = session['name']
                encPassword = base64.b64encode(password.encode("utf-8"))
                connection = sql_connection()
                table_created = create_register_table(connection)
                if table_created==0:
                    datetime = time.ctime()
                    sql_query = "INSERT INTO public.register_table_dispatch_details (username, password, email_id,datetime) VALUES (%s, %s, %s,%s);"
                    curr = connection.cursor()
                    curr.execute(sql_query, (name, encPassword, email,datetime))
                    connection.commit()
                    connection.close()
                else:
                    raise ConnectionError()

                #remove session after adding it to table
                session.pop('password')
                session.pop('name')
                session.pop('token')

                flash("Signup successful! Please login.", "success")
                del password,name,encPassword,sql_query
                gc.collect()
                return redirect(url_for('login_page'))
            else:
                # return "Invalid token. Please try again.", 400
                flash("Invalid code. Please try again.", "error")  # Flash error message

        return render_template('validate_mail.html', email=email)

    except ConnectionError as exe:
        return jsonify({'error': str(exe)}),400

@app.route('/validate_mail_reset_password',methods=['POST','GET'])
def validate_mail_reset_password():
    email = request.args.get('email')  # Retrieve email from query string
    if request.method == 'POST':
        entered_token = str(request.form['token'])

        # Compare the entered token with the session token
        if str(session.get('reset_token')) == str(entered_token):
            return redirect(url_for('reset_password'))
        else:
            # return "Invalid token. Please try again.", 400
            flash("Invalid code. Please try again.", "error")  # Flash error message

    return render_template('reset_token_validate.html', email=email)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    try:
        if request.method == 'POST':
            email = session['email']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
            if not password_pattern.match(new_password):
                flash("Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character.", "error")
                return render_template('reset_password.html')

            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template('reset_password.html')
            # Check password strength using regex
            else:
                encPassword = base64.b64encode(new_password.encode("utf-8"))
                sql_query = "UPDATE public.register_table_dispatch_details SET password = %s WHERE email_id = %s;"
                connection = sql_connection()
                if connection == 'Connection Error':
                    raise PgConnectionError()
                else:
                    curr = connection.cursor()
                    curr.execute(sql_query,(encPassword,email))
                    connection.commit()
                    connection.close()

                    flash("Password has been reset successfully. You can now log in.", "success")
                del encPassword,sql_query
                gc.collect()

                return redirect(url_for('login_page'))
        return render_template('reset_password.html')
    except PgConnectionError as exe:
        return jsonify({'error':str(exe)})


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    try:
        if request.method == 'POST':
            email = request.form['email']
            session['email'] = email
            sql_query = f"SELECT * FROM public.register_table_dispatch_details WHERE email_id = '{email}';"
            connection = sql_connection()
            if connection == 'Connection Error':
                raise PgConnectionError()
            else:
                curr = connection.cursor()
                curr.execute(sql_query)
                rows = curr.fetchall()
                connection.close()

            if len(rows) == 0:
                flash("Email not found. Please SignUp", "error")
                return redirect(url_for('signup'))
            else:
                # Generate a random token
                reset_token = str(random.randint(100000, 999999))
                session['reset_token'] = reset_token
                subject = "Code For Password Change"
                body = f"Your verification code is {reset_token}. Please enter it on the website to verify your email."
                message = f"Subject: {subject}\n\n{body}"
                msg = send_mail(email, message)

                del reset_token,subject,body,message
                gc.collect()

                if msg == 0:
                    flash("Code has been sent to registered email id.", "info")
                    return redirect(url_for('validate_mail_reset_password', email=email))

            del email,sql_query,rows
            gc.collect()
        return render_template('forgot_password.html')

    except PgConnectionError as exe:
        return jsonify({'error':str(exe)})
    




def rate_comparision(raw_data_excel, rate_table_master_excel):
    df = pd.read_excel(raw_data_excel)
    df.rename(columns={'TOTAL_CALC_AMT': "Rate MT"}, inplace=True)
    df["Amount"] = df["Billed Quantity"] * df["Rate MT"]
    
    df = df.sort_values(["Description", "Rate MT"], ascending=[True, True])
    df["Level"] = df.groupby("Description").cumcount() + 1
    df = df[df["Level"] <= 3].copy()
    
    rows = []
    nec_order = ["Billed Quantity", "Rate MT", "Plant", "Mode of Transport", "Distance in KM", "Amount"]
    
    for desc, g in df.groupby("Description"):
        row_block = {}
        for _, r in g.iterrows():
            level_name = "L" + str(r["Level"]) + " Mode"
            row_block[level_name] = {
                "Billed Quantity": r["Billed Quantity"],
                "Rate MT": r["Rate MT"],
                "Plant": r["Plant"],
                "Mode of Transport": r["Mode of Transport"],
                "Distance in KM": r["Distance in KM"],
                "Amount": r["Amount"]
            }
        
        for nec in nec_order:
            row = {"Description (Destination)": desc, "Attributes": nec}
            for i in range(1, 4):
                level_name = "L" + str(i) + " Mode"
                row[level_name] = row_block.get(level_name, {}).get(nec)
            rows.append(row)
    
    final_df = pd.DataFrame(rows)
    
    # Use .copy() to avoid SettingWithCopyWarning
    df1 = final_df[final_df['Attributes'].isin(['Billed Quantity', 'Rate MT', 'Amount'])].copy()
    df2 = final_df[~final_df['Attributes'].isin(['Billed Quantity', 'Rate MT', 'Amount'])].copy()
    df2['Grand Total'] = None
    
    # Use infer_objects to avoid FutureWarning
    df1 = df1.fillna(0).infer_objects(copy=False)
    
    df1['Grand Total'] = df1['L1 Mode'] + df1['L2 Mode'] + df1['L3 Mode']
    df1.loc[df1['Attributes'] == 'Rate MT', 'Grand Total'] = 0
    
    amt_gt = df1[df1['Attributes'] == 'Amount'].set_index('Description (Destination)')['Grand Total']
    qty_gt = df1[df1['Attributes'] == 'Billed Quantity'].set_index('Description (Destination)')['Grand Total']
    calc = (amt_gt / qty_gt).fillna(0)
    
    df1.loc[df1['Attributes'] == 'Rate MT', 'Grand Total'] = (
        df1.loc[df1['Attributes'] == 'Rate MT', 'Description (Destination)'].map(calc)
    )
    
    # Filter out empty DataFrames before concatenation
    dfs_to_concat = [df for df in [df1, df2] if not df.empty]
    if dfs_to_concat:
        final_df = pd.concat(dfs_to_concat, axis=0, ignore_index=False)
    else:
        final_df = pd.DataFrame()
    
    final_df['Grand Total'] = round(final_df['Grand Total'], 1)
    final_df_1 = final_df.copy()
    
    final_df_1.loc[final_df_1['Attributes'] == 'Billed Quantity', 'Attributes'] = '1 Billed Quantity'
    final_df_1.loc[final_df_1['Attributes'] == 'Rate MT', 'Attributes'] = '2 Rate MT'
    final_df_1.loc[final_df_1['Attributes'] == 'Amount', 'Attributes'] = '3 Amount'
    final_df_1.loc[final_df_1['Attributes'] == 'Plant', 'Attributes'] = '4 Plant'
    final_df_1.loc[final_df_1['Attributes'] == 'Mode of Transport', 'Attributes'] = '5 Mode of Transport'
    final_df_1.loc[final_df_1['Attributes'] == 'Distance in KM', 'Attributes'] = '6 Distance in KM'
    final_df_1.sort_values(['Description (Destination)', 'Attributes'], inplace=True)
    
    rate_df = pd.read_excel(rate_table_master_excel)
    rate_df_1 = rate_df[["Plant", "Dest. Desc.", "MODE", "Total with STO"]].copy()
    rate_df_1 = rate_df_1[rate_df_1['Total with STO'] != 0]
    rate_df_1.sort_values(['Dest. Desc.', 'Total with STO'], ascending=True, inplace=True)
    
    df_final = rate_df_1.loc[rate_df_1.groupby('Dest. Desc.')['Total with STO'].idxmin()].copy()
    
    rows = []
    for desc, g in df_final.groupby("Dest. Desc."):
        row_block = {}
        for _, r in g.iterrows():
            level_name = "Lowest cost route"
            row_block[level_name] = {
                "Billed Quantity": None,
                "Rate MT": r["Total with STO"],
                "Plant": r["Plant"],
                "Mode of Transport": r["MODE"],
                "Distance in KM": None,
                "Amount": None
            }
        
        for nec in nec_order:
            row = {"Description (Destination)": desc, "Attributes": nec}
            row[level_name] = row_block.get(level_name, {}).get(nec)
            rows.append(row)
    
    rate_final_df = pd.DataFrame(rows)
    rate_final_df.loc[rate_final_df['Attributes'] == 'Billed Quantity', 'Attributes'] = '1 Billed Quantity'
    rate_final_df.loc[rate_final_df['Attributes'] == 'Rate MT', 'Attributes'] = '2 Rate MT'
    rate_final_df.loc[rate_final_df['Attributes'] == 'Amount', 'Attributes'] = '3 Amount'
    rate_final_df.loc[rate_final_df['Attributes'] == 'Plant', 'Attributes'] = '4 Plant'
    rate_final_df.loc[rate_final_df['Attributes'] == 'Mode of Transport', 'Attributes'] = '5 Mode of Transport'
    rate_final_df.loc[rate_final_df['Attributes'] == 'Distance in KM', 'Attributes'] = '6 Distance in KM'
    rate_final_df.sort_values(['Description (Destination)', 'Attributes'], inplace=True)
    
    rate_final_df.set_index(['Description (Destination)', 'Attributes'], inplace=True)
    final_df_1.set_index(['Description (Destination)', 'Attributes'], inplace=True)
    
    df_merged = final_df_1.join(rate_final_df, how='inner')
    df_merged = df_merged.reset_index()
    
    df_merged.loc[df_merged["Attributes"] == "1 Billed Quantity", 'Lowest cost route'] = \
        df_merged.loc[df_merged["Attributes"] == "1 Billed Quantity", 'Grand Total']
    
    for dest in df_merged['Description (Destination)'].unique():
        mask_amount = (df_merged['Description (Destination)'] == dest) & (df_merged['Attributes'] == '3 Amount')
        mask_rate = (df_merged['Description (Destination)'] == dest) & (df_merged['Attributes'] == '2 Rate MT')
        mask_qty = (df_merged['Description (Destination)'] == dest) & (df_merged['Attributes'] == '1 Billed Quantity')
        
        rate_val = df_merged.loc[mask_rate, 'Lowest cost route'].values[0]
        qty_val = df_merged.loc[mask_qty, 'Lowest cost route'].values[0]
        
        df_merged.loc[mask_amount, 'Lowest cost route'] = rate_val * qty_val
    
    # Use .copy() to avoid SettingWithCopyWarning
    final_df1 = df_merged[df_merged['Attributes'] != '3 Amount'].copy()
    final_df1['Total Gain(Lowest cost route - Grand Total)'] = 0
    
    final_df2 = df_merged[df_merged['Attributes'] == '3 Amount'].copy()
    final_df2['Total Gain(Lowest cost route - Grand Total)'] = final_df2['Lowest cost route'] - final_df2['Grand Total']
    
    result_df = pd.concat([final_df1, final_df2], axis=0, ignore_index=False)
    result_df.sort_values(['Description (Destination)', 'Attributes'], inplace=True)
    
    bqty_df = result_df[result_df['Attributes'] == "1 Billed Quantity"].sort_values('Grand Total', ascending=False)
    Total_bill_qty = sum(list(bqty_df['Grand Total']))
    
    amount_df = result_df[result_df['Attributes'] == "3 Amount"].sort_values('Grand Total', ascending=False)
    Total_Amount = sum(list(amount_df['Grand Total']))
    lowest_coust_route_total = sum(list(amount_df['Lowest cost route']))
    Amount_differance = Total_Amount - lowest_coust_route_total
    
    bqty_20_df = bqty_df.iloc[:20]
    not_bqty_df = result_df[result_df['Attributes'] != "1 Billed Quantity"]
    unqiue_dest = list(bqty_20_df['Description (Destination)'].unique())
    non_bqty_20_df = not_bqty_df[not_bqty_df['Description (Destination)'].isin(unqiue_dest)]
    
    top_20_df = pd.concat([bqty_20_df, non_bqty_20_df], axis=0, ignore_index=False)
    top_20_df = top_20_df[top_20_df['Attributes'].isin(['1 Billed Quantity','3 Amount'])]
    top_20_df.sort_values(['Description (Destination)', 'Attributes'], inplace=True)
    
    final_result_dict = {
        'result_df': result_df,
        'top_20_df': top_20_df,
        'total_Amount': round(Total_Amount, 2),
        'lowest_coust_route_total': round(lowest_coust_route_total, 2),
        'amount_differance': round(Amount_differance, 2)
    }
    
    return final_result_dict



@app.route('/upload')
def index():
    return render_template('index.html')


# @app.route('/upload_files', methods=['POST'])
# def upload_files():
#     try:
#         if 'email' not in session:
#             app.logger.debug(f"Session data: {session.items()}")
#             flash("Please log in to access this functionality.", "error")
#             return redirect(url_for('login_page'))

#         # if method is get then we will get data from session
#         if request.method == "GET":
#             email = session.get("email")

#             if not email:
#                 return "Email not found in session", 400

#             # Condition for DataFrame stored as JSON
#             if session.get(f"{email}_result_df"):
#                 result_df_json = session[f"{email}_result_df"]
#                 result_df = pd.read_json(result_df_json)
#             else:
#                 result_df = None

#             # Condition for unique sales list
#             if session.get(f"{email}_unique_sales"):
#                 unique_sales = session[f"{email}_unique_sales"]
#             else:
#                 unique_sales = None

#             return render_template('result_page.html', sales_orders=unique_sales, result_df=result_df)

#         else:

#             email = session['email']

#             # Validate files
#             if 'pending_order_file' not in request.files or 'rate_file' not in request.files or 'stock_file' not in request.files:
#                 flash('No file part')
#                 return redirect(request.url)

#             pending_order_file = request.files['pending_order_file']
#             rate_file = request.files['rate_file']
#             stock_file = request.files['stock_file']

#             if not (allowed_file(pending_order_file.filename) and allowed_file(rate_file.filename) and allowed_file(stock_file.filename)):
#                 flash('Invalid file format. Please upload Excel files only.')
#                 return redirect(request.url)


#             # Save files into the unique user folder
#             filename1 = secure_filename(pending_order_file.filename)
#             filename2 = secure_filename(rate_file.filename)
#             filename3 = secure_filename(stock_file.filename)

#             pending_order_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename1))
#             rate_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename2))
#             stock_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename3))

#             file_path1 = os.path.join(app.config['UPLOAD_FOLDER'], filename1)
#             file_path2 = os.path.join(app.config['UPLOAD_FOLDER'], filename2)
#             file_path3 = os.path.join(app.config['UPLOAD_FOLDER'], filename3)

#             result_df1, rate_stck_df_c1 = order_assignment_func(file_path1, file_path2, file_path3)

#             # Extract unique Sales Order values from result_df1
#             unique_sales_orders = [int(i) for i in result_df1['Sales Order'].unique() if pd.notna(i)]

#             session[email + '_result_df'] = base64.b64encode(pickle.dumps(result_df1)).decode('utf-8')
#             session[email+'_unique_sales'] = unique_sales_orders

#             return render_template('result_page.html', sales_orders=unique_sales_orders, result_df=result_df1)

#     except Exception as e:
#         tb = traceback.format_exc()   # get full traceback as string
#         print("traceback",tb)
#         return str(e)



@app.route('/upload_files', methods=["GET",'POST'])
def upload_files():
    try:
        if 'email' not in session:
            app.logger.debug(f"Session data: {session.items()}")
            flash("Please log in to access this functionality.", "error")
            return redirect(url_for('login_page'))
        
        if request.method == "GET":
            email = session.get("email")

            if not email:
                return "Email not found in session", 400
            
            result_data = session.get(f"{email}_result_data")
            result_data = pickle.loads(base64.b64decode(result_data))
            top_20_data = session.get(f"{email}_top_20_data")
            top_20_data = pickle.loads(base64.b64decode(top_20_data))
            print("result_data:",result_data)
            # print("top_20_data:",top_20_data)


            columns = session.get(f"{email}_columns")
            total_amount =  session.get(f"{email}_total_amount")
            lowest_cost =  session.get(f"{email}_lowest_cost") 
            amount_diff =  session.get(f"{email}_amount_diff")

            # print("columns:",columns)
            # print("total_amount:",total_amount)
            # print("lowest_cost::",lowest_cost)
            # print("amount_diff::",amount_diff)


            return render_template('results.html',
                            result_data=result_data,
                            top_20_data=top_20_data,
                            columns=columns,
                            total_amount=total_amount,
                            lowest_cost=lowest_cost,
                            amount_diff=amount_diff)
         
            # else:
            #     session[email + "_result_data"] = base64.b64encode(pickle.dumps(result_data)).decode("utf-8")
            #     session[email + "_top_20_data"] = base64.b64encode(pickle.dumps(top_20_data)).decode("utf-8")
            #     session[email + "_total_amount"] = results['total_Amount']
            #     session[email + "_lowest_cost"] = results['lowest_coust_route_total']
            #     session[email + "_amount_diff"] = results['amount_differance']
            #     return render_template('results.html',
            #                  result_data=result_data,
            #                  top_20_data=top_20_data,
            #                  columns=columns,
            #                  total_amount=results['total_Amount'],
            #                  lowest_cost=results['lowest_coust_route_total'],
            #                  amount_diff=results['amount_differance'])
        email = session.get("email")
        if 'pending_order_file' not in request.files or 'rate_file' not in request.files:
            return "Missing files", 400
        
        pending_file = request.files['pending_order_file']
        rate_file = request.files['rate_file']
        
        if pending_file.filename == '' or rate_file.filename == '':
            return "No files selected", 400
        
        pending_filename = secure_filename(pending_file.filename)
        rate_filename = secure_filename(rate_file.filename)
        
        pending_path = os.path.join(app.config['UPLOAD_FOLDER'], pending_filename)
        rate_path = os.path.join(app.config['UPLOAD_FOLDER'], rate_filename)
        
        pending_file.save(pending_path)
        rate_file.save(rate_path)
        
        results = rate_comparision(pending_path, rate_path)
        
        result_data = results['result_df'].to_dict('records')
        top_20_data = results['top_20_df'].to_dict('records')
        columns = list(results['result_df'].columns)
        print('pending path:',pending_path)
        print('pending path:',rate_path)
        os.remove(pending_path.replace("\\","/"))
        os.remove(rate_path.replace('\\','/'))

        session[email + "_result_data"] = base64.b64encode(pickle.dumps(result_data)).decode("utf-8")
        session[email + "_top_20_data"] = base64.b64encode(pickle.dumps(top_20_data)).decode("utf-8")
        session[email + "_total_amount"] = results['total_Amount']
        session[email + "_lowest_cost"] = results['lowest_coust_route_total']
        session[email + "_amount_diff"] = results['amount_differance']
        session[email + "_columns"] = columns


        return render_template('results.html',
                             result_data=result_data,
                             top_20_data=top_20_data,
                             columns=columns,
                             total_amount=results['total_Amount'],
                             lowest_cost=results['lowest_coust_route_total'],
                             amount_diff=results['amount_differance'])
    
    except Exception as e:
        import traceback
        error_msg = f"Error processing files: {str(e)}<br><br>Traceback:<br><pre>{traceback.format_exc()}</pre>"
        return error_msg, 500

@app.route('/download/<report_type>')
def download(report_type):
    try:
        output = io.BytesIO()
        if 'email' not in session:
            flash("Please log in to access this functionality.", "error")
            return redirect(url_for('login_page'))
    
        email = session['email']

        if report_type == 'full':
            data = session.get(email + '_result_data')
            df = pd.DataFrame(pickle.loads(base64.b64decode(data)))
            
            filename = 'full_results.xlsx'
        elif report_type == 'top20':
            data = session.get(email + '_result_data')
            df = pd.DataFrame(pickle.loads(base64.b64decode(data)))

            filename = 'top_20_results.xlsx'
        else:
            return "Invalid report type", 400
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Results')
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        return f"Error downloading file: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)