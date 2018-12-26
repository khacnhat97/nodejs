//Import package
var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');
//PASSWORD Ultils
//CREATE Function to ramdom salt
var genRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')//convert to hexa format
        .slice(0, length);
};

var sha512 = function (password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};
function saltHashPassWord(userPassword) {
    var salt = genRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}
function checkHashPassword(userPassword, salt) {
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}
//Create Express Service
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//Create MongoDB Client
var MongoClient = mongodb.MongoClient;

//Connection URL
var url = 'mongodb://localhost:27017' // is default port
MongoClient.connect(url,{useNewUrlParser: true}, function(err, client){
    if(err)
        console.log('Khong the ket noi den mongoDB server.Error', err);
    else {
        //Dang Ki
        app.post('/register', (request, response, next) => {
            var post_data = request.body;

            var plaint_password = post_data.password;
            var hash_data = saltHashPassWord(plaint_password);

            var password = hash_data.passwordHash;//luu mat khau hash
            var salt = hash_data.salt; //luu salt
             
            var name = post_data.name;
            var email = post_data.email;
            var insertJson = {
                'email': email,
                'password': password,
                'salt': salt,
                'name': name
            };
            var db = client.db('devnodejs');
            //Kiem tra trung email
            db.collection('user')
               .find({'email':email}).count(function(err,number){
                   if(number!=0)
                   {
                       response.json('Email đã được đăng ký');
                       console.log('Email da duoc dang ky');
                   }
                   else
                   {
                       //Them du lieu
                       db.collection('user')
                           .insertOne(insertJson,function(error,res){
                               response.json('Đăng ký thành công');
                               console.log('Dang ky thanh cong');
                           })
                   }
               })
            });
        app.post('/login', (request, response, next) => {
            var post_data = request.body;

            var email = post_data.email;
            var userPassword = post_data.password;
            var db = client.db('devnodejs');
            //Kiem tra trung email
            db.collection('user')
               .find({ 'email': email }).count(function (err, number) {
                   if (number == 0) {
                       response.json('Email chưa đăng ký');
                       console.log('Email chua dang ky');
                   }
                   else
                   {
                       //Them du lieu
                       db.collection('user')
                           .findOne({ 'email': email }, function (err, user) {
                               var salt = user.salt; // get salt tu user
                               var hashed_password = checkHashPassword(userPassword, salt).passwordHash;//hash password
                               var encrypted_password = user.password; //get password tu user
							   var ten = user.name;
                               if (hashed_password == encrypted_password)
                               {
                                   response.json('Đăng nhập thành công. Tên: '+ten);
                                   console.log('Dang nhap thanh cong');
                               }
                               else {
                                   response.json('Sai mật khẩu');
                                   console.log('Sai mat khau');
                               }
                           })
                   }
               })
        });
        //start web server
        app.listen(3000,()=>{
            console.log('Ket noi MongoDB Server, WebService running on port 3000');
        })
    }
});