import tkinter, csv, os, re, bcrypt, pyotp, smtplib, webbrowser
from tkinter import messagebox
from password_validator import PasswordValidator

#Interfaces Section

#User Login - Main Page
def main():
    global window, username_entry, password_entry, prompt_label
    window = tkinter.Tk()
    w, h = window.winfo_screenwidth(), window.winfo_screenheight()
    window.title("Login form")
    window.geometry("%dx%d+0+0" % (w, h))
    window.configure(bg='#333333')
    frame = tkinter.Frame(bg='#333333')
    # Creating widgets
    login_label = tkinter.Label(
        frame, text="Grocery Store - Login", bg='#333333', fg="#FF3399", font=("Arial", 30))
    username_label = tkinter.Label(
        frame, text="Username/Email", bg='#333333', fg="#FFFFFF", font=("Arial", 16))
    username_entry = tkinter.Entry(frame, font=("Arial", 16))
    password_entry = tkinter.Entry(frame, show="*", font=("Arial", 16))
    password_label = tkinter.Label(
        frame, text="Password", bg='#333333', fg="#FFFFFF", font=("Arial", 16))
    login_button = tkinter.Button(
        frame, text="Login", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10, command=login)
    register_button = tkinter.Button(frame, text="Register", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10, command=registerScreen)
    readme_button = tkinter.Button(frame, text="Read me!", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10, command=openweb)
    # Placing widgets on the screen
    login_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
    username_label.grid(row=1, column=0)
    username_entry.grid(row=1, column=1, pady=20)
    password_label.grid(row=2, column=0, sticky="w")
    password_entry.grid(row=2, column=1, pady=20)
    login_button.grid(row=3, column=0, columnspan=1, pady=30)
    register_button.grid(row=3, column=1, columnspan=1, pady=30)
    readme_button.grid(row=3, column=2, columnspan=1, pady=30)
    frame.pack()
    window.mainloop()

#One-time password screen
def otpScreen(t_otp): 
    global window1, otp_entry, amount, total
    from functools import partial
    window.destroy()
    window1 = tkinter.Tk()
    w1, h1 = window1.winfo_screenwidth(), window1.winfo_screenheight()
    window1.title("OTP screen")
    window1.geometry("%dx%d+0+0" % (w1, h1))
    window1.configure(bg='#333333')
    frame1 = tkinter.Frame(bg='#333333')
    #Create a countdown
    amount = 60
    total = "Confirm the One-Time Password sent to your email within {} seconds".format(str(amount))
    def countdown():
        global amount
        amount = amount - 1
        total = "Confirm the One-Time Password sent to your email within {} seconds".format(str(amount))
        if amount == 0:
            messagebox.showerror(title="OPT", message="OTP pin has elaped")
            window1.destroy()
            main()
        # Update the label text using string    
        otp_message.config(text=total)    
        otp_message.after(1000,countdown)  
    # Creating widgets
    otp_label = tkinter.Label(frame1, text="Grocery Store - OPT", bg='#333333', fg="#FF3399", font=("Arial", 30))
    otp_message = tkinter.Label(frame1, text=total, bg='#333333', fg="#FF3399", font=("Arial", 16))
    otp_entry = tkinter.Entry(frame1, font=("Arial", 16))
    #Used partial to club a function and the var t_otp and passed it to otp_button via command
    action_with_arg = partial(validateOtp, t_otp)
    otp_button = tkinter.Button(frame1, text="Submit", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10, command=action_with_arg)
    # Placing widgets on the screen
    otp_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
    otp_message.grid(row=2, column=0, columnspan=2, sticky="news", pady=40)
    otp_entry.grid(row=4, column=0, columnspan=2, pady=20)
    otp_button.grid(row=5, column=0, columnspan=2, pady=20)
    frame1.pack()
    #call the calldown function every 1s
    countdown()   
    window1.mainloop()

#New User Register Screen
def registerScreen():
    global window2, reg_email_entry, reg_fn_entry, reg_sur_entry, reg_pw_entry
    window.destroy()
    window2 = tkinter.Tk()
    w2, h2 = window2.winfo_screenwidth(), window2.winfo_screenheight()
    window2.title("OTP screen")
    window2.geometry("%dx%d+0+0" % (w2, h2))
    window2.configure(bg='#333333')
    frame2 = tkinter.Frame(bg='#333333')
    # Creating widgets
    reg_label = tkinter.Label(frame2, text="Grocery Store - Register", bg='#333333', fg="#FF3399", font=("Arial", 30)) 
    reg_email_label = tkinter.Label(frame2, text="Email", bg='#333333', fg="#FFFFFF", font=("Arial", 16))
    reg_fn_label = tkinter.Label(frame2, text="First Name", bg='#333333', fg="#FFFFFF", font=("Arial", 16))
    reg_sur_label = tkinter.Label(frame2, text="Surname", bg='#333333', fg="#FFFFFF", font=("Arial", 16))
    reg_pw_label = tkinter.Label(frame2, text="Password", bg='#333333', fg="#FFFFFF", font=("Arial", 16))
    reg_email_entry = tkinter.Entry(frame2, font=("Arial", 16))
    reg_fn_entry = tkinter.Entry(frame2, font=("Arial", 16))
    reg_sur_entry = tkinter.Entry(frame2, font=("Arial", 16))
    reg_pw_entry = tkinter.Entry(frame2, font=("Arial", 16), show="*")
    reg_submit_button = tkinter.Button(frame2, text="Submit", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10, command=saveNewUser)
    # Placing widgets on the screen
    reg_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
    reg_email_label.grid(row=1, column=0)
    reg_fn_label.grid(row=2, column=0)
    reg_sur_label.grid(row=3, column=0)
    reg_pw_label.grid(row=4, column=0)
    reg_email_entry.grid(row=1, column=1, pady=20)
    reg_fn_entry.grid(row=2, column=1, pady=20)
    reg_sur_entry.grid(row=3, column=1, pady=20)
    reg_pw_entry.grid(row=4, column=1, pady=20)
    reg_submit_button.grid(row= 5, pady=20, columnspan=3)
    frame2.pack()
    window2.mainloop()

#Products Screen [this is only to confirm that the user has logged in sucessfully]
def productsScreen(): 
    window1.destroy()
    window3 = tkinter.Tk()
    w3, h3 = window3.winfo_screenwidth(), window3.winfo_screenheight()
    window3.title("Grocery Store - Products")
    window3.geometry("%dx%d+0+0" % (w3, h3))
    window3.configure(bg='#333333')
    frame3 = tkinter.Frame(bg='#333333')
    # Creating widgets
    prod_label = tkinter.Label(frame3, text="Grocery Store - Products", bg='#333333', fg="#FF3399", font=("Arial", 30)) 
    prod_auth_label = tkinter.Label(frame3, text="You have successfully logged in to the Grocery Store! Products will be available soon!", bg='#333333', fg="#FF3399", font=("Arial", 16)) 
    # Placing widgets on the screen
    prod_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
    prod_auth_label.grid(row=1, column=0)
    frame3.pack()
    window3.mainloop()

#Main Functions Section

#This function checks: 
#(1) whether a CVS file exists by calling the function checkCVSFileExists();
#(2) whether the user and password entered match the user and password saved in the CSV file named userdatabase.
def login():
    path = os.path.join(os.getcwd(), "userdatabase.csv")
    if checkCVSFileExists():
        if (openCSVReturnUserPw(path, username_entry.get(), password_entry.get())): 
            t_opt = send_otp_to_email(username_entry.get())
            messagebox.showinfo("OPT", "An OTP was sent your email account!")
            otpScreen(t_opt)
        else:
            messagebox.showerror(title="Error", message="Invalid login - User/Password incorrect or account doesn't exit")
    else: 
        messagebox.showerror(title="Error", message="Invalid login - User/Password incorrect or account doesn't exit")

#This function open a link using the default web browser
def openweb():
    webbrowser.open("https://github.com/lucasrbenion/GroceryShopProject1",new=1)

#This funtion validates if the OTP sent to a registed eamil account has been the same keyed in by the user
def validateOtp(t_otp):
    otp_entered = otp_entry.get()
    if t_otp.verify(otp_entered)==True:
        messagebox.showinfo("Login", "Successul Secure Login using 2FA")
        productsScreen()
    else:
        messagebox.showerror(title="Failed", message= "OTP entered does not match!! Please try again...")

#This functon checks whether a CSV named userdatabase exists in the project folder
def checkCVSFileExists():
    path = os.path.join(os.getcwd(), "userdatabase.csv")
    if os.path.exists(path):
        return True
    else:
        return False

#This function checks if a value/entry exists in the CVS file named userdatabase
def check_value_in_csv(csv_file_path, value):
  # Open the CSV file in read mode.
  with open(csv_file_path, "r") as csv_file:
    # Iterate over the rows in the CSV file.
    reader = csv.reader(csv_file)
    for row in reader:
      # Check if the value to search for is in the row.
      if value in row:
        return True
  # The value was not found in the CSV file.
  return False

#Function to verify that the password greater than 8 characters, has at least one uppercase character, has at least one digit and one special character
def validatePassword(password):
    meets_criteria = bool
    pw = PasswordValidator()
    pw.min(8).max(15).has().uppercase().has().lowercase().has().digits().has().symbols()
    meets_criteria = pw.validate(password)
    return meets_criteria

#Function to verify if the entered email is valid 
def is_valid_email(email):
    # Check if the email address is valid
    if not re.match(r"^[a-zA-Z0-9.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        return False
    return True

#This function encrypts a password and retuned using bcrypt and return hashed random password
def EncrypPassword(password):
    salt = bcrypt.gensalt() # randomness
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

#This function checks if the password keyed in by the user matches the hashed password
def check_password(password, hashed_password):
    p = password.encode('utf-8')
    hp = hashed_password.encode('utf-8')
    return bcrypt.checkpw(p,hp)

#This function updates an item in a dictionary
def updateItemDict(dictionary, key, value):
  # Get the list of values for the key.
  unencrypted = dictionary.get(key, [])
  # Add the new value to the list.
  dictionary[key] = value
  return dictionary

#This function opens the CVS file named userdatabase and returs True if the user and password are in the CVS file
def openCSVReturnUserPw(csv_file_path, user, pwinput):
  # Open the CSV file in read mode.
  with open(csv_file_path, "r") as csv_file:
    # Iterate over the rows in the CSV file.
    reader = csv.reader(csv_file)
    for row in reader:
        # Check if the User & Password are in the CSV file
        if user in row:
            if check_password(pwinput,row[3]):
                return True
    return False
  
#This function sends an OTP(one-time password), calls the send_email function and then returns the temporary OTP 
def send_otp_to_email(email):
  #generate a random OTP for 60 seconds  
  totp = pyotp.TOTP('base32secret3232', interval=60)

  # Send the OTP to the email address.
  send_email(email, "OTP Password", "Your OTP is: {0}".format(totp.now()))

  # Return the OTP.
  return totp

#This function sends an email containing a temporary OTP to the user's registed account 
def send_email(email, subject, message):
  # Create a SMTP connection.
  connection = smtplib.SMTP('smtp.gmail.com', 587)
  connection.ehlo()
  # Start a TLS connection.
  connection.starttls()
  connection.ehlo()
  # Login to the account.
  connection.login('lucasrbennion@gmail.com', 'zaaappysqdxifemc')
  # Send the email.
  connection.sendmail('lucasrbennion@gmail.com', email,
                     'Subject: {0}\n\n{1}'.format(subject, message))
  # Close the connection.
  connection.close()

#This function saves a new user into a cvs file and then returns to the main screen
def saveNewUser(): 
    #gets the user info and saves into a cvs file
    user_credentials = {"email": reg_email_entry.get(), "first_name": reg_fn_entry.get(), "surname": reg_sur_entry.get(), "password": reg_pw_entry.get()}
    
    if checkCVSFileExists():
        path = os.path.join(os.getcwd(), "userdatabase.csv")
        if check_value_in_csv(path, reg_email_entry.get()):
            messagebox.showerror('Error', 'User already registed under this email!')
        else:
            with open("userdatabase.csv", mode="a") as csvfile:
                fieldnames = user_credentials.keys()
                while is_valid_email(reg_email_entry.get()) == False:
                    messagebox.showerror('Error', 'Please insert a valid email')
                    registerScreen()
                while (reg_fn_entry.get =="" or reg_sur_entry.get() ==""):
                    messagebox.showerror('Error', 'Insert your name & surname!')
                    registerScreen()
                while validatePassword(reg_pw_entry.get()) == False:
                    messagebox.showerror('Error', 'Invalid password: your passord needs to have at least 8 characters, one being uppercase, one being a digit and one being a special character')
                    registerScreen()
                utf = EncrypPassword(reg_pw_entry.get())
                user_credentials = updateItemDict(user_credentials, "password", utf.decode('utf-8'))
                writer = csv.DictWriter(csvfile,fieldnames, lineterminator='\n')
                writer.writerow(user_credentials)
                messagebox.showinfo("New Account", "Your account has been sucessfully created!")
    else:
        with open("userdatabase.csv", mode="w") as csvfile:
            fieldnames = user_credentials.keys()
            while is_valid_email(reg_email_entry.get()) == False:
                messagebox.showerror('Error', 'Please insert a valid email')
                registerScreen()
            while (reg_fn_entry.get =="" or reg_sur_entry.get() ==""):
                messagebox.showerror('Error', 'Insert your name & surname!')
                registerScreen()
            while validatePassword(reg_pw_entry.get()) == False:
                messagebox.showerror('Error', 'Invalid password: your passord needs to have at least 8 characters, one being uppercase, one being a digit and one being a special character')
                registerScreen()
            utf = EncrypPassword(reg_pw_entry.get())
            user_credentials = updateItemDict(user_credentials, "password", utf.decode('utf-8'))
            writer = csv.DictWriter(csvfile, fieldnames, lineterminator='\n')
            writer.writerow(user_credentials)
            messagebox.showinfo("New Account", "Your account has been sucessfully created!")
    window2.destroy()
    main()

if __name__ == "__main__":
    main()