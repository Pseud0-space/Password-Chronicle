from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QLineEdit, QMessageBox, QRadioButton
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyrebase
import base64
import json
import sys
import os

class Security():
    global backend
    global iv
    backend = default_backend()
    iv = b'\xc62\xb3\x8d\x94z(\xb2\xbc\x13^\x18\r.\x92\xa7'
    key = b""

    def decrypt(inp):
        paa = inp.encode()
        b64 = base64.b64decode(paa)
        cipher = Cipher(algorithms.AES(Security.key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        dec = decryptor.update(b64) + decryptor.finalize()
        return dec.rstrip().decode()

    def padding(data):
        while len(data) % 16 != 0:
            data = data + " "
        return data

    def encrypt(inp):
        padded_msg = Security.padding(inp).encode()
        cipher = Cipher(algorithms.AES(Security.key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_msg) + encryptor.finalize()
        b64 = base64.b64encode(ct).decode()
        return b64

class Store:
    mail = ""

class FirebaseConfig():
    self.config = { "FIREBASE_CONFIG_OBJECT" } 
    
   '''I know, I am adding these two un-necessary functions, but just for the sake 
   of making it more understandable to someone who never worked with pyrebase'''

    def DatabaseConfig(self):
        jsonConfig = self.config
        return jsonConfig

    def AuthConfig(self):
        jsonConfig = self.config
        return jsonConfig


class Ui_main(object):
    def setupUi(self, Fetch):
        Fetch.setObjectName("Fetch")
        Fetch.setFixedSize(810, 260)
        Fetch.setStyleSheet("background-color: rgb(78, 78,78);\n"
                            "color: rgb(255, 255, 255);\n"
                            "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(Fetch)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(270, 30, 281, 31))
        self.label.setObjectName("label")
        self.fetchButton = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton.setGeometry(QtCore.QRect(80, 130, 211, 61))
        self.fetchButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton.setObjectName("fetchButton")
        self.fetchButton.clicked.connect(self.con1)
        self.fetchButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton_2.setGeometry(QtCore.QRect(300, 130, 211, 61))
        self.fetchButton_2.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton_2.setObjectName("fetchButton_2")
        self.fetchButton_2.clicked.connect(self.con2)

        self.fetchButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton_3.setGeometry(QtCore.QRect(520, 130, 211, 61))
        self.fetchButton_3.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton_3.setObjectName("fetchButton_2")
        self.fetchButton_3.clicked.connect(self.con3)

        Fetch.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(Fetch)
        self.statusbar.setObjectName("statusbar")
        Fetch.setStatusBar(self.statusbar)

        self.retranslateUi(Fetch)
        QtCore.QMetaObject.connectSlotsByName(Fetch)

    def retranslateUi(self, Fetch):
        _translate = QtCore.QCoreApplication.translate
        Fetch.setWindowTitle(_translate("Fetch", "Password Chronicle"))
        self.label.setText(_translate("Fetch", "<html><head/><body><p align=\"center\"><span style=\" font-size:17pt; text-decoration: underline;\">Password Chronicle</span></p></body></html>"))
        self.fetchButton.setText(_translate("Fetch", "Login"))
        self.fetchButton_2.setText(_translate("Fetch", "Sign Up"))
        self.fetchButton_3.setText(_translate("Fetch", "Password Reset"))

    def con1(self):
        self.win = Ui_Login()
        self.win.show()

    def con2(self):
        self.win = Ui_Signup()
        self.win.show()

    def con3(self):
        self.win = Ui_Reset()
        self.win.show()


class Ui_Login(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_Login, self).__init__()

        self.setObjectName("Login")
        self.setFixedSize(525, 280)
        self.setStyleSheet("background-color: rgb(77, 77, 77);\n"
                                "color: rgb(255, 255, 255);\n"
                                "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(185, 15, 181, 41))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(60, 90, 91, 31))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(60, 140, 81, 31))
        self.label_3.setObjectName("label_3")
        self.loginButton = QtWidgets.QPushButton(self.centralwidget)
        self.loginButton.setGeometry(QtCore.QRect(180, 200, 181, 51))
        self.loginButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "font: 12pt \"Lucida Handwriting\";\n"
                                        "border-radius : 20%")
        self.loginButton.setObjectName("loginButton")
        self.loginButton.clicked.connect(self.backend)
        self.idLine = QtWidgets.QLineEdit(self.centralwidget)
        self.idLine.setGeometry(QtCore.QRect(160, 90, 291, 31))
        self.idLine.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                "font: 11pt \"Lucida Fax\";\n"
                                "border-radius : 15%;")
        self.idLine.setObjectName("idLine")
        self.passLIne = QtWidgets.QLineEdit(self.centralwidget)
        self.passLIne.setGeometry(QtCore.QRect(160, 140, 291, 31))
        self.passLIne.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                        "font: 11pt \"Lucida Fax\";\n"
                                        "border-radius : 15%;")
        self.passLIne.setObjectName("passLIne")
        self.passLIne.setEchoMode(QLineEdit.Password)
        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        QtCore.QMetaObject.connectSlotsByName(self)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Login", "Login"))
        self.label.setText(_translate("Login", "<html><head/><body><p align=\"center\"><span style=\" font-size:16pt; text-decoration: underline;\">LOGIN</span></p></body></html>"))
        self.label_2.setText(_translate("Login", "<html><head/><body><p>Enter Email ID</p></body></html>"))
        self.label_3.setText(_translate("Login", "<html><head/><body><p align=\"center\">Password</p></body></html>"))
        self.loginButton.setText(_translate("Login", "LOGIN"))

    def ShwError(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("Invalid ID or Password")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def backend(self):
        firebaseConfig = FirebaseConfig().AuthConfig()
        dbConfig = FirebaseConfig().DatabaseConfig()
        fireDB = pyrebase.initialize_app(dbConfig)
        fire = pyrebase.initialize_app(firebaseConfig)

        db = fireDB.database()
        authentication = fire.auth()
        status = ""

        email  = self.idLine.text()
        password = self.passLIne.text()
        try:
            authentication.sign_in_with_email_and_password(email, password)
            status =  True
        except :
            status = False
            self.ShwError()

        if status == True:
            Store.mail = str(email)
            if Store.mail == str(email):
                self.win = Ui_Connect()
                data = db.child(Store.mail.replace(".", "_")).child("PC_SECURITY").get().val()
                dynamic = ""

                for i in data:
                    dynamic += i
                datakey = data[dynamic]["PCS_KEY"]
                PCS_KEY = base64.b64decode(datakey.encode())
                Security.key = PCS_KEY

                self.win.show()


class Ui_Signup(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_Signup, self).__init__()
        
        self.setObjectName("Sign Up")
        self.setFixedSize(525, 310)
        self.setStyleSheet("background-color: rgb(77, 77, 77);\n"
                                "color: rgb(255, 255, 255);\n"
                                "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(180, 15, 181, 41))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(60, 80, 91, 31))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(60, 125, 81, 31))
        self.label_3.setObjectName("label_3")
        self.loginButton = QtWidgets.QPushButton(self.centralwidget)
        self.loginButton.setGeometry(QtCore.QRect(180, 230, 181, 51))
        self.loginButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "font: 12pt \"Lucida Handwriting\";\n"
                                        "border-radius : 20%")
        self.loginButton.setObjectName("loginButton")

        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(30, 170, 120, 31))
        self.label_4.setObjectName("label_4")


        self.loginButton.clicked.connect(self.backend)
        self.idLine = QtWidgets.QLineEdit(self.centralwidget)
        self.idLine.setGeometry(QtCore.QRect(160, 80, 291, 31))
        self.idLine.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                "font: 11pt \"Lucida Fax\";\n"
                                "border-radius : 15%;")
        self.idLine.setObjectName("idLine")

        self.confirmLine = QtWidgets.QLineEdit(self.centralwidget)
        self.confirmLine.setGeometry(QtCore.QRect(160, 170, 291, 31))
        self.confirmLine.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                        "font: 11pt \"Lucida Fax\";\n"
                                        "border-radius : 15%;")
        self.confirmLine.setObjectName("confirmLine")

        self.passLIne = QtWidgets.QLineEdit(self.centralwidget)
        self.passLIne.setGeometry(QtCore.QRect(160, 125, 291, 31))
        self.passLIne.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                        "font: 11pt \"Lucida Fax\";\n"
                                        "border-radius : 15%;")
        self.passLIne.setObjectName("passLIne")
        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        QtCore.QMetaObject.connectSlotsByName(self)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Login", "Sign Up"))
        self.label.setText(_translate("Login", "<html><head/><body><p align=\"center\"><span style=\" font-size:16pt; text-decoration: underline;\">SIGN UP</span></p></body></html>"))
        self.label_2.setText(_translate("Login", "<html><head/><body><p>Enter Email ID</p></body></html>"))
        self.label_3.setText(_translate("Login", "<html><head/><body><p align=\"center\">Password</p></body></html>"))
        self.label_4.setText(_translate("Login", "<html><head/><body><p align=\"center\">Confirm Password</p></body></html>"))
        self.loginButton.setText(_translate("Login", "SIGN UP"))

    def ShwSuc(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Signup Completed successfully, Email Verification sent")
        msgBox.setWindowTitle("SUCCESS")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def ShwError(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("Email already registered")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass
    
    def ShwError1(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("Password too short, should be more than 6 characters")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def backend(self):
        firebaseConfig = FirebaseConfig().AuthConfig()
        dbConfig = FirebaseConfig().DatabaseConfig()

        fire = pyrebase.initialize_app(firebaseConfig)
        fireDB = pyrebase.initialize_app(dbConfig)
        db = fireDB.database()
        authentication = fire.auth()

        email = self.idLine.text()
        password = self.passLIne.text()
        confirm = self.confirmLine.text()
            
        if confirm == password:
            try:
                if len(password) >= 6:
                    user = authentication.create_user_with_email_and_password(email, password)
                    token = user['idToken']
                    authentication.send_email_verification(token)

                    child = str(email).replace(".","_")
                    key = os.urandom(32)
                    data = {"PCS_KEY" : f"{base64.b64encode(key).decode()}"}
                    db.child(f"{child}").child("PC_SECURITY").push(data)

                    self.ShwSuc()

                else:
                    self.ShwError1()

            except Exception as e:
                print(e)
                self.ShwError()


class Ui_Reset(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_Reset, self).__init__()
        
        self.setObjectName("Password Reset")
        self.setFixedSize(525, 255)
        self.setStyleSheet("background-color: rgb(77, 77, 77);\n"
                        "color: rgb(255, 255, 255);\n"
                        "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(170, 20, 200, 41))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(60, 100, 91, 31))
        self.label_2.setObjectName("label_2")

        self.loginButton = QtWidgets.QPushButton(self.centralwidget)
        self.loginButton.setGeometry(QtCore.QRect(180, 170, 181, 51))
        self.loginButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "font: 12pt \"Lucida Handwriting\";\n"
                                        "border-radius : 20%")
        self.loginButton.setObjectName("loginButton")
        self.loginButton.clicked.connect(self.backend)
        self.idLine = QtWidgets.QLineEdit(self.centralwidget)
        self.idLine.setGeometry(QtCore.QRect(160, 100, 291, 31))
        self.idLine.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                "font: 11pt \"Lucida Fax\";\n"
                                "border-radius : 15%;")
        self.idLine.setObjectName("idLine")

        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        QtCore.QMetaObject.connectSlotsByName(self)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Login", "Password Reset"))
        self.label.setText(_translate("Login", "<html><head/><body><p align=\"center\"><span style=\" font-size:16pt; text-decoration: underline;\">PASSWORD RESET</span></p></body></html>"))
        self.label_2.setText(_translate("Login", "<html><head/><body><p>Enter Email ID</p></body></html>"))
        self.loginButton.setText(_translate("Login", "Send Email"))

    def ShwError(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("Invalid Email")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def ShwSuc(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Reset Email Sent")
        msgBox.setWindowTitle("SUCCESS")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def backend(self):
        firebaseConfig = FirebaseConfig().AuthConfig()
        fire = pyrebase.initialize_app(firebaseConfig)
        authentication = fire.auth()

        email  = self.idLine.text()
        try:
            authentication.send_password_reset_email(email)
            self.ShwSuc()
        except :
            self.ShwError()


class Ui_Connect(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_Connect, self).__init__()
        self.setFixedSize(840, 270)
        self.setStyleSheet("background-color: rgb(78, 78,78);\n"
                        "color: rgb(255, 255, 255);\n"
                        "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(281, 30, 281, 31))
        self.label.setObjectName("label")
        self.fetchButton = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton.setGeometry(QtCore.QRect(90, 130, 211, 61))
        self.fetchButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                "border-radius : 25%;\n"
                                "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton.setObjectName("fetchButton")
        self.fetchButton.clicked.connect(self.ret)
        self.fetchButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton_2.setGeometry(QtCore.QRect(315, 130, 211, 61))
        self.fetchButton_2.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton_2.setObjectName("fetchButton_2")
        self.fetchButton_2.clicked.connect(self.gen)

        self.fetchButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton_3.setGeometry(QtCore.QRect(540, 130, 211, 61))
        self.fetchButton_3.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton_3.setObjectName("fetchButton_3")
        self.fetchButton_3.clicked.connect(self.upd)

        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

        self.show()

    def retranslateUi(self, Fetch):
        _translate = QtCore.QCoreApplication.translate
        Fetch.setWindowTitle(_translate("Fetch", "The Chronicle"))
        self.label.setText(_translate("Fetch", "<html><head/><body><p align=\"center\"><span style=\" font-size:18pt; text-decoration: underline;\">The Chronicle</span></p></body></html>"))
        self.fetchButton.setText(_translate("Fetch", "Password Retriever"))
        self.fetchButton_2.setText(_translate("Fetch", "Password Storer"))
        self.fetchButton_3.setText(_translate("Fetch", "Password Manager"))

    def ret(self):
        self.win = Ui_Fetch()
        self.win.show()

    def gen(self):
        self.win = Ui_PassStore()
        self.win.show()
    
    def upd(self):
        self.win = Ui_Manage()
        self.win.show()


class Ui_Fetch(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_Fetch, self).__init__()
        datalst = []
        firebaseConfig = FirebaseConfig().DatabaseConfig()
        fire = pyrebase.initialize_app(firebaseConfig)
        db = fire.database()

        mail = str(Store.mail).replace(".","_")
        try: 
            global data
            data = db.child(mail).get().val()
        except:
            self.ShwError()

        for i in data:
            if str(i) != "PC_SECURITY":
                datalst.append(str(i))
            
        self.setObjectName("Fetch")
        self.setFixedSize(811, 361)
        self.setStyleSheet("background-color: rgb(76, 76,76);\n"
                                "color: rgb(255, 255, 255);\n"
                                "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(280, 20, 281, 31))
        self.label.setObjectName("label")
        self.useBox = QtWidgets.QComboBox(self.centralwidget)
        self.useBox.setGeometry(QtCore.QRect(380, 110, 211, 31))
        self.useBox.setStyleSheet("background-color: rgb(101, 101, 101);\n"
                                "border-radius : 15%;\n"
                                "font: 13pt \"MS Shell Dlg 2\";")
        self.useBox.setObjectName("useBox")
        self.useBox.addItems(datalst)

        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(220, 110, 151, 31))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(160, 190, 101, 31))
        self.label_3.setObjectName("label_3")
        self.passLine = QtWidgets.QLineEdit(self.centralwidget)
        self.passLine.setGeometry(QtCore.QRect(270, 190, 381, 31))
        self.passLine.setStyleSheet("background-color: rgb(99, 99, 99);\n"
                                "border-radius:15%;\n"
                                "font: 12pt \"Lucida Fax\";")
        self.passLine.setObjectName("passLine")
        self.fetchButton = QtWidgets.QPushButton(self.centralwidget)
        self.fetchButton.setGeometry(QtCore.QRect(340, 260, 161, 61))
        self.fetchButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.fetchButton.setObjectName("fetchButton")
        self.fetchButton.clicked.connect(self.backend)
        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        QtCore.QMetaObject.connectSlotsByName(self)
        _translate = QtCore.QCoreApplication.translate

        self.setWindowTitle(_translate("Fetch", "Show Password"))
        self.label.setText(_translate("Fetch", "<html><head/><body><p align=\"center\"><span style=\" font-size:18pt; text-decoration: underline;\">Password Retriever</span></p></body></html>"))
        self.label_2.setText(_translate("Fetch", "<html><head/><body><p><span style=\" font-size:12pt;\">Use of Password</span></p></body></html>"))
        self.label_3.setText(_translate("Fetch", "<html><head/><body><p><span style=\" font-size:12pt;\">Password : </span></p></body></html>"))
        self.fetchButton.setText(_translate("Fetch", "Retrieve"))

    def ShwError(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("Error Fetching Data")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass


    def backend(self):
        firebaseConfig = FirebaseConfig().DatabaseConfig()
        fire = pyrebase.initialize_app(firebaseConfig)
        db = fire.database()
        use = self.useBox.currentText()
        st = Store.mail
        mail = st.replace(".","_")

        data = db.child(mail).get().val()

        dynamic = ""

        for i in data[use]:
            dynamic += i

        passwrd = data[use][dynamic]["Password"]
        self.passLine.setText(Security.decrypt(passwrd))


class Ui_PassStore(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_PassStore, self).__init__()
        self.setObjectName("PassGenerator")
        self.setFixedSize(800, 330)
        self.setStyleSheet("background-color: rgb(80, 80, 80);\n"
                        "color: rgb(255, 255, 255);\n"
                        "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")

        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(273, 20, 281, 31))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(200, 100, 151, 31))
        self.label_2.setObjectName("label_2")
        self.useLine = QtWidgets.QLineEdit(self.centralwidget)
        self.useLine.setGeometry(QtCore.QRect(360, 100, 251, 31))
        self.useLine.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                        "font: 11pt \"Lucida Fax\";\n"
                                        "border-radius : 15%;")
        self.useLine.setObjectName("useLine")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(150, 160, 151, 31))
        self.label_3.setObjectName("label_3")
        self.passLine = QtWidgets.QLineEdit(self.centralwidget)
        self.passLine.setGeometry(QtCore.QRect(290, 160, 381, 31))
        self.passLine.setStyleSheet("background-color: rgb(100, 100, 100);\n"
                                        "font: 11pt \"Lucida Fax\";\n"
                                        "border-radius : 15%;")
        self.passLine.setObjectName("passLine")
    
        self.saveButton = QtWidgets.QPushButton(self.centralwidget)
        self.saveButton.setGeometry(QtCore.QRect(305, 230, 211, 61))
        self.saveButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "font: 12pt \"Lucida Handwriting\";\n"
                                        "border-radius : 20%")
        self.saveButton.setObjectName("saveButton")
        self.saveButton.clicked.connect(self.backend)
        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        QtCore.QMetaObject.connectSlotsByName(self)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("PassGenerator", "Store Password"))
        self.label.setText(_translate("PassGenerator", "<html><head/><body><p align=\"center\"><span style=\" font-size:16pt; text-decoration: underline;\">PASSWORD STORING</span></p></body></html>"))
        self.label_2.setText(_translate("PassGenerator", "<html><head/><body><p align=\"center\"><span style=\" font-size:11pt;\">Use of Password : </span></p></body></html>"))
        self.label_3.setText(_translate("PassGenerator", "<html><head/><body><p><span style=\" font-size:11pt;\">Password Used : </span></p></body></html>"))
        self.saveButton.setText(_translate("PassGenerator", "Save Password"))

    def ShwSuc(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Password Saved Sucessfully")
        msgBox.setWindowTitle("SUCCESS")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass


    def backend(self):
        firebaseConfig = FirebaseConfig().DatabaseConfig()
        fire = pyrebase.initialize_app(firebaseConfig)
        db = fire.database()

        use = self.useLine.text()
        password = self.passLine.text()
        child = str(Store.mail).replace(".","_")

        data = {"Password" : f"{Security.encrypt(password)}"}
        db.child(f"{child}").child(f"{use}").push(data)

        self.ShwSuc()


class Ui_Manage(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui_Manage, self).__init__()
        datalst = []
        firebaseConfig = FirebaseConfig().DatabaseConfig()
        fire = pyrebase.initialize_app(firebaseConfig)
        db = fire.database()

        mail = str(Store.mail).replace(".","_") 
        data = db.child(mail).get().val()

        try:
                for i in data:
                    if str(i) != "PC_SECURITY":
                        datalst.append(str(i))
        
        except :
                self.ShwError()

        self.setObjectName("Fetch")
        self.resize(810, 400)
        self.setStyleSheet("background-color: rgb(76, 76,76);\n"
                                "color: rgb(255, 255, 255);\n"
                                "font: 10pt \"Lucida Fax\";")
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(280, 30, 281, 31))
        self.label.setObjectName("label")
        self.useBox = QtWidgets.QComboBox(self.centralwidget)
        self.useBox.setGeometry(QtCore.QRect(380, 110, 211, 31))
        self.useBox.setStyleSheet("background-color: rgb(101, 101, 101);\n"
                                "border-radius : 15%;\n"
                                "font: 13pt \"MS Shell Dlg 2\";")
        self.useBox.setObjectName("useBox")
        self.useBox.addItems(datalst)

        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(220, 110, 151, 31))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(150, 170, 190, 31))
        self.label_3.setObjectName("label_3")
        self.passLine = QtWidgets.QLineEdit(self.centralwidget)
        self.passLine.setGeometry(QtCore.QRect(340, 170, 320, 30))
        self.passLine.setStyleSheet("background-color: rgb(99, 99, 99);\n"
                                "border-radius:15%;\n"
                                "font: 12pt \"Lucida Fax\";")
        self.passLine.setObjectName("passLine")

        self.delRadio = QRadioButton(self)
        self.delRadio.setText("DELETE")
        self.delRadio.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 12pt \"Cambria\";\n"
                                   "background-color: rgb(76, 76,76);\n")
        self.delRadio.setGeometry(QtCore.QRect(330, 235, 100, 32))

        self.updateRadio = QRadioButton(self)
        self.updateRadio.setText("UPDATE")
        self.updateRadio.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 12pt \"Cambria\";\n"
                                   "background-color: rgb(76, 76,76);\n")
        self.updateRadio.setGeometry(QtCore.QRect(430, 235, 100, 32))

        self.manageButton = QtWidgets.QPushButton(self.centralwidget)
        self.manageButton.setGeometry(QtCore.QRect(315, 300, 200, 61))
        self.manageButton.setStyleSheet("background-color: rgb(52, 179, 30);\n"
                                        "border-radius : 25%;\n"
                                        "font: 11pt \"Lucida Handwriting\";")
        self.manageButton.setObjectName("manageButton")
        self.manageButton.clicked.connect(self.backend)
        self.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        QtCore.QMetaObject.connectSlotsByName(self)
        _translate = QtCore.QCoreApplication.translate

        self.setWindowTitle(_translate("Fetch", "Password Manager"))
        self.label.setText(_translate("Fetch", "<html><head/><body><p align=\"center\"><span style=\" font-size:18pt; text-decoration: underline;\">Password Manager</span></p></body></html>"))
        self.label_2.setText(_translate("Fetch", "<html><head/><body><p><span style=\" font-size:12pt;\">Use of Password</span></p></body></html>"))
        self.label_3.setText(_translate("Fetch", "<html><head/><body><p><span style=\" font-size:12pt;\">Password (For Update) </span></p></body></html>"))
        self.manageButton.setText(_translate("Fetch", "Manage Password"))

        self.show()

    def ShwSuc(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Password Updated Sucessfully")
        msgBox.setWindowTitle("SUCCESS")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def ShwSucRmv(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Password Deleted Sucessfully")
        msgBox.setWindowTitle("SUCCESS")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass
    
    def ShwError(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("No Task Selected")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def ShwErrorWeak(self):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText("Weak Password. Password size should be more than 6 characters")
        msgBox.setWindowTitle("ERROR")

        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def backend(self):
        firebaseConfig = FirebaseConfig().DatabaseConfig()
        fire = pyrebase.initialize_app(firebaseConfig)
        db = fire.database()
        mail = str(Store.mail).replace(".","_")

        use = self.useBox.currentText()

        if self.updateRadio.isChecked():
            password = self.passLine.text()
            if len(password) >= 6:
                dat = db.child(mail).get().val()

                static = ""

                for i in dat[use]:
                        static += i

                data = {"Password" : f"{Security.encrypt(password)}"}
                db.child(f"{mail}").child(f"{use}").child(static).update(data)

                self.ShwSuc()
            
            else:
                self.ShwErrorWeak()
        
        elif self.delRadio.isChecked():
            db.child(f"{mail}").child(f"{use}").remove()

            self.ShwSucRmv()

        else:
            self.ShwError()

app = QtWidgets.QApplication(sys.argv)
Fetch = QtWidgets.QMainWindow()
ui = Ui_main()
ui.setupUi(Fetch)
Fetch.show()
sys.exit(app.exec_())
