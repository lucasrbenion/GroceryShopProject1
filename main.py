import tkinter, csv, os, re, bcrypt, pyotp
from tkinter import messagebox
from password_validator import PasswordValidator

#Interface
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
    readme_button = tkinter.Button(frame, text="Read me!", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10)
    output_label = tkinter.Label(
        window, text="Optput", bg='#333333', fg="#FF3399", font=("Arial", 15))
    prompt_label = tkinter.Label(
        window, text="", bg='#333333', fg="#FF3399", font=("Arial", 15))
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
    output_label.pack()
    #show results to use (row=5, column=0, columnspan=2, sticky="w", pady=40)
    prompt_label.pack()
    window.mainloop()

def otpScreen(): 
    global window1
    window.destroy()
    window1 = tkinter.Tk()
    w1, h1 = window1.winfo_screenwidth(), window1.winfo_screenheight()
    window1.title("OTP screen")
    window1.geometry("%dx%d+0+0" % (w1, h1))
    window1.configure(bg='#333333')
    frame1 = tkinter.Frame(bg='#333333')
    # Creating widgets
    otp_label = tkinter.Label(frame1, text="Grocery Store - OPT", bg='#333333', fg="#FF3399", font=("Arial", 30))
    otp_message = tkinter.Label(frame1, text="Confirm your One-Time Password sent to your email within {count down}", bg='#333333', fg="#FF3399", font=("Arial", 16))
    otp_entry = tkinter.Entry(frame1, font=("Arial", 16))
    otp_button = tkinter.Button(frame1, text="Submit", bg="#FF3399", fg="#FFFFFF", font=("Arial", 16), height= 1, width=10, command=otpEmail)
    # Placing widgets on the screen
    otp_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
    otp_message.grid(row=2, column=0, columnspan=2, sticky="news", pady=40)
    otp_entry.grid(row=4, column=0, columnspan=2, pady=20)
    otp_button.grid(row=5, column=0, columnspan=2, pady=20)
    frame1.pack()
    window1.mainloop()

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

#Main Functions
def login():
    path = os.path.join(os.getcwd(), "userdatabase.csv")
    if (openCSVReturnUserPw(path, username_entry.get(), password_entry.get())): 
        send_otp_to_email(username_entry.get())
        otpScreen()
        messagebox.showerror(title="OPT", message="An OTP was sent your email account!")
    else:
        messagebox.showerror(title="Error", message="Invalid login.")
        prompt_label.config(text="Invalid login - User/Password incorrect or account doesn't exit")


#write a function that sends a OTP to an email and then validate if it was inserted by the user correctly. 
def otpEmail(): 
    productsScreen()

def checkCVSFileExists():
    path = os.path.join(os.getcwd(), "userdatabase.csv")
    if os.path.exists(path):
        return True
    else:
        return False

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
    print(pw.validate(password))
    meets_criteria = pw.validate(password)
    return meets_criteria

#Function to verify if the entered email is valid 
def is_valid_email(email):
    # Check if the email address is valid
    if not re.match(r"^[a-zA-Z0-9.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        return False
    return True

class User: 
    def __init__(self, email, name, surname, password):
        self.email = email 
        self.name = name
        self.surname= surname
        self.password= password 

#create an encrypt password function using bcrypt?
def EncrypPassword(password):
    salt = bcrypt.gensalt() # randomness
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(password, hashed_password):
    print(password, hashed_password)
    p = password.encode('utf-8')
    hp = hashed_password.encode('utf-8')
    return bcrypt.checkpw(p,hp)

#This function updates an item in a dictionary
def updateItemDict(dictionary, key, value):
  # Get the list of values for the key.
  unencrypted = dictionary.get(key, [])
  print(unencrypted)
  # Add the new value to the list.
  dictionary[key] = value
  print(dictionary)  
  return dictionary

def openCSVReturnUserPw(csv_file_path, user, pwinput):
  # Open the CSV file in read mode.
  with open(csv_file_path, "r") as csv_file:
    # Iterate over the rows in the CSV file.
    reader = csv.reader(csv_file)
    print(reader)
    for row in reader:
        # Check if the User & Password are in the CSV file
        if user in row:
            if check_password(pwinput,row[3]):
                return True
    return False
  
def send_otp_to_email(email):
  """Sends an OTP to an email address using the pyotp extension.

  Args:
    email: The email address to send the OTP to.
    secret: The secret key for the OTP generator.

  Returns:
    The OTP that was sent.
  """

  # Create an OTP generator.
  otp = pyotp.TOTP('base32secret3232')

  # Send the OTP to the email address.
  send_email(email, "OTP Password", "Your OTP is: {0}".format(otp))

  # Return the OTP.
  return otp

import smtplib

def send_email(email, subject, message):
  """Sends an email to a registered email address.

  Args:
    email: The email address to send the email to.
    subject: The subject of the email.
    message: The body of the email.
  """

  # Create a SMTP connection.
  connection = smtplib.SMTP('smtp.gmail.com', 587)
  connection.ehlo()
  # Start a TLS connection.
  connection.starttls()
  connection.ehlo()

  # Login to the account.
  connection.login('lucasrbennion@gmail.com', 'Esogtr18floki@')

  # Send the email.
  connection.sendmail('lucasrbennion@gmail.com', email,
                     'Subject: {0}\n\n{1}'.format(subject, message))

  # Close the connection.
  connection.close()


#save a new user into a cvs file or datate (whatever is easier) and then return to the main screen
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
                while validatePassword(reg_pw_entry.get()) == False:
                    messagebox.showerror('Error', 'Invalid password: your passord needs to have at least 8 characters, one being uppercase, one being a digit and one being a special character')
                    registerScreen()
                print(user_credentials)
                utf = EncrypPassword(reg_pw_entry.get())
                user_credentials = updateItemDict(user_credentials, "password", utf.decode('utf-8'))
                writer = csv.DictWriter(csvfile,fieldnames, lineterminator='\n')
                writer.writerow(user_credentials)
    else:
        with open("userdatabase.csv", mode="w") as csvfile:
            fieldnames = user_credentials.keys()
            utf = EncrypPassword(reg_pw_entry.get())
            user_credentials = updateItemDict(user_credentials, "password", utf.decode('utf-8'))
            writer = csv.DictWriter(csvfile, fieldnames, lineterminator='\n')
            writer.writerow(user_credentials)
    window2.destroy()
    main()

if __name__ == "__main__":
    main()