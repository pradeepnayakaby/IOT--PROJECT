from flask import Flask, render_template, request, redirect, url_for, session
import re
import os
from flask import Flask, flash, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
import numpy as np
import cv2
import matplotlib.pyplot as plt
import numpy as np
import os
import PIL
import tensorflow as tf
from csv import writer
import pandas as pd
from flask_material import Material
import cv2
import joblib
import cv2
from flask import send_from_directory
import math
# Define the upload folder
UPLOAD_FOLDER = 'static/uploads/'



app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.secret_key = '1a2b3c4d5e'


ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif','bmp'])
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

model = joblib.load('iotattack.pkl')


@app.route('/',methods=['GET', 'POST'])
def login():
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        
                # If account exists in accounts table in out database
        if username=="admin" and password=="admin":
            # Create session data, we can access this data in other routes
            # Redirect to home page
            return render_template('index.html')
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    return render_template('login.html', msg=msg)

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')



@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    prediction_text = ""
    if request.method == 'POST':
        # Collect form data
        features = [
            request.form['src_port'],
            request.form['dst_port'],
            request.form['flow_duration'],
            request.form['fwd_pkt_len_std'],
            request.form['flow_pkts_s'],
            request.form['flow_iat_mean'],
            request.form['flow_iat_std'],
            request.form['flow_iat_max'],
            request.form['fwd_iat_tot'],
            request.form['bwd_iat_max'],
            request.form['bwd_pkts_s'],
            request.form['ack_flag_cnt'],
            request.form['init_bwd_win_byts'],
            request.form['idle_mean'],
            request.form['idle_max']
        ]
        
        # Convert inputs to a numpy array
        input_features = np.array(features).reshape(1, -1)
        
        # Make prediction
        prediction = model.predict(input_features)
        
        # Convert prediction to a readable text
        if prediction[0] == 1:
            prediction_text = "Normal"
        else:
            prediction_text = "Anomaly"
            return render_template('service.html', prediction_text=prediction_text)
    return render_template('service.html')

    
@app.route('/display/<filename>')
def display_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)





@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
