
# Grocery Store

The project aims to showcase how users should authenticate to a Grocery Store application through a complex password and 2FA (Two-factor authentication) using the python modules "pyotp" and "password_validator". Further, once a user account is created the password is encrypted using module "bcrypt" and then saved in a CVS file located in the project folder to ensure the password is not known to anyone other than the user. 

## Main Modules
* Tkinter: this is a powerful and flexible GUI toolkit that allows to create user-friendly and interactive applications with ease. It provides a wide range of widgets and tools that can be used to design and customize the interface.
* CVS: this module is used to read and write data in CSV (Comma Separated Values) format. Once the module has been imported, the various functions are provided to work with CSV files. For example, the csv.reader() function to read data from a CSV file, and the csv.writer() function to write data to a CSV file.
* Bycrypt: the Bcrypt function in Python is a popular way to securely hash passwords. It uses a salt to make each hash unique and adds an additional layer of security against brute-force attacks.
* Smtplib: module used to send emails using Python. This module defines an SMTP client session object that can be used to send mail to any Internet machine with an SMTP or ESMTP listener daemon.









 


## Running the application

Download the project zip file submitted to the University of Essex under LCYS_PCOM7E May 2023 -> Unit 12 -> End of Module Assignment or download the code and readme file from GitHub: https://github.com/lucasrbenion/GroceryShopProject1

Unzip the project zip file into your Python project folder. Make sure Python 3.11.4 is installed and the path is set your Python Projects folder. 

```bash
    cd C:\PythonProjects\GroceryShop>
    python main.py
```
    
## Usage/Examples - Key functions

The function below verifies that a password is greater than 8 characters and a maximum of 15 characters; has at least one uppercase character, one digit, and one special character. The function returns a bool (boolean), which means that the password passed as an argument either meets the criteria or not.

```
def validatePassword(password):
    meets_criteria = bool
    pw = PasswordValidator()
    pw.min(8).max(15).has().uppercase().has().lowercase().has().digits().has().symbols()
    meets_criteria = pw.validate(password)
    return meets_criteria
```
The other important function below is responsible for encrypting a password passed as an argument and returning a hashed random password using the bcrypt module calling the function gensalt().

```
def EncrypPassword(password):
    salt = bcrypt.gensalt() # randomness
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed
```
The next function sends an OTP(one-time password) to the user's registered email by calling the send_email function and then returns the temporary OTP generated to be checked against the user's keyed-in OPT PIN. 

```
def send_otp_to_email(email):
  #generate a random OTP for 60 seconds  
  totp = pyotp.TOTP('base32secret3232', interval=60)

  # Send the OTP to the email address.
  send_email(email, "OTP Password", "Your OTP is: {0}".format(totp.now()))

  # Return the OTP.
  return totp
```
## System Workflow and Tests

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Login.PNG)
|:--:|
| **Login Screen:** Main screen of the application |

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Login%20-%20Try_to_Login_with_no_username%26password.PNG)
|:--:|
| **Login Screen:** User tries to Login without typing a username or password|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Login%20-%20Try_to_Login_with_unregistered_username.PNG)
|:--:|
| **Login Screen:** User tries to Login with an unregistered username|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Register%20-%20Validate_Email.PNG)
|:--:|
| **Register Screen:** User clicks on Register and tries to input an invalid email (missing @). 
Subsequently, the user clicks submit.|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Register%20-%20Validate_FirstName_Surname_not_empt.PNG)
|:--:|
| **Register Screen:** User leaves FirstName and Surname blank and then tries to submit|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Register%20-%20Password_needs_complexity.PNG)
|:--:|
| **Register Screen:** User leaves password and tries to submit. |
| A pop up warning message requests the user to create a complex password |

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Register%20-%20all_criteria_met.PNG)
|:--:|
| **Register Screen:** User fills in the form and meets all criteria |

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Register%20-%20cvs_created_with_encrypted_password.PNG)
|:--:|
| **CVS File:** A CVS file is created with all user details |

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Login%20-%20OTP_sent_to_email.PNG)
|:--:|
| **Login Screen:** User enters their credentials and then an OPT pin is sent to their account |

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20OTP%20-%20OTP_received.PNG)
|:--:|
| **OPT Screen:** (1) An OPT temporary pin is received by the user|
| (2) A system 60 seconds countdown starts|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20OTP%20-%20OTP_expired_after_60_secs.PNG)
|:--:|
| **OPT Screen:** The OPT temporary pin expiries and after 60s and the user needs to Login again|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20OTP%20-%20OTP_correctly_entered.PNG)
|:--:|
| **OPT Screen:** User enters the correct OTP pin and is securely logged to the application|

![App Screenshot](https://raw.githubusercontent.com/lucasrbenion/GroceryShopProject1/main/screenshots/GroceryShop%20-%20Products%20-%20User_logged_in_sucessfully.PNG)
|:--:|
| **Products Screen:** User will be able to see the Grocery Products once this functionally is available|




## Authors

- [Lucas Rodrigues Bennion](https://github.com/lucasrbenion/GroceryShopProject1)

