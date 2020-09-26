const express = require('express');
const pool = require('../db');
const fs = require('fs');
const bcrypt = require('bcrypt');
const { match } = require('assert');
let router = express.Router();

//Automatically created file with user data locally
function writeDataInFile(filename) {
    const query = 'SELECT * FROM users;'
    pool.query(query)
        .then(res => {
            res.rows.forEach((el,index) => {
                if(index === 0){
                    fs.writeFile(filename, JSON.stringify({
                        user: el.username,
                    }) + '\n', err => {
                    if (err) throw err; 
                    console.log('File created and admin added!');
                    })
                }
                else 
                    fs.appendFile(filename, JSON.stringify({
                        user: el.username,
                        pass: el.userpass,
                        block: el.userblock,
                        passlimit: el.passlimit,
                        }) + '\n', err => {
                        if(err) throw err;
                        console.log('Data inserted!'); 
                    })
            })
        })
        .catch(err => console.log('Error while writing data in file', err.stack));
}

writeDataInFile('data.txt');

//Global variables that determine the user
let currentUser = {
    attempts: 3,
};
let loggedIn = false;
let blocked = [];

//Function checks pass form user and hashed from DB 
async function checkUser(pass, hashed) {
    if(currentUser.name == 'ADMIN' && pass === 'admin') return true;
    let result = await bcrypt.compare(pass, hashed);
    console.log('User password: ' + pass + '\nHashed password: ' + hashed + '\nResult: ' + result);

    return result;
}

//Function checks user password if it was limited by ADMIN
function validateLimitedPassword(password) {
    console.log('pass: ' + password + '\nValidation of limited password');
    console.log(password.match('[+=/:%*-]+') !== null);
    console.log(password.match('[A-Za-z]+') !== null);

    if(password.match('[+=/:%*-]+') !== null && password.match('[A-Za-z]+') !== null)
        return true; 
    else 
        return false;
}

//Function in order to store plain passwords for ADMIN 
function storeAndUpdatePassword(user, plainpass, process){
    if(process == 'insert'){
        pool.query(`INSERT INTO "forAdmin" (name, password)
                    VALUES ('${user}', '${plainpass}');`)
                    .then(() => console.log('Inserted user data into pivate table'))
                    .catch((err) => console.error(err));
    }
    else if(process == 'update'){
        pool.query(`UPDATE "forAdmin" SET name='${user}', password='${plainpass}' WHERE name='${user}';`)
                    .then(() => console.log('Updated user data in private table!'))
                    .catch((err) => console.error(err));
    } 
    else if(process == 'delete'){
        pool.query(`DELETE FROM "forAdmin" WHERE name='${user}'`)
            .then(() => console.log('Deleted user data from private table!'))
            .catch(e => console.error(e));
    }
}


//Login page 
router.get('/', (req,res) => {
   return res.render('auth-pages/login');
})

//Send credentials in order to log in
router.post('/', (req,res) => {
    let errors = [];
    if(currentUser.name !== req.body.loginUsername)
        currentUser.attempts = 3;

    //currentUser now has his temporary name and pass
    currentUser.name = req.body.loginUsername;
    currentUser.pass = req.body.loginPassword;

    //Blocking as user tried log in 3 times
    if(blocked.indexOf(currentUser.name) !== -1){
        errors.push({msg: `User with ${currentUser.name} is still blocked!`})
        return res.render('auth-pages/login', {
            errors,
            disabled: 'disabled',
        })
    }

    //find in DB if user exists: 
    //if yes -> check password : 
    //      yes -> passed || no -> error: incorrect name or pass
    //if no -> error: there is no such user 
    const query = `SELECT * FROM users WHERE username = '${currentUser.name}';`;
    let validator;
    pool.query(query)
        .then(result => {
            validator = result.rows[0];
            if(validator){
                //if user is bloked by admin he wont be able to log in 
                if(validator.userblock){
                    errors.push({msg: `User with ${currentUser.name} username is blocked by Admin!`})
                    return res.render('auth-pages/login', {
                            errors,
                            disabled: 'disabled',
                    })
                }
                //if user has not got a password - he should enter it
                if(validator.userpass === ''){
                    currentUser.id = validator._id;
                    currentUser.passlimit = validator.passlimit;
                    return res.redirect(`/auth/register/${currentUser.name}`);
                } 
                else {  
                checkUser(currentUser.pass, validator.userpass)
                    .then((result) => {
                        if(result){
                            currentUser.id = validator._id;
                            currentUser.passlimit = validator.passlimit;
                            loggedIn = true; 

                            console.log('User is validated');
                            return res.redirect(`/auth/main/${currentUser.name}`);
                        }
                        else{
                            // user entered wrong password
                                currentUser.attempts -= 1;
                                let disabled = '';
                            // if user run out of attempts, he will be blocked
                                if(currentUser.attempts == 0){
                                    disabled = 'disabled';
                                    blocked.push(currentUser.name);
                                    console.log(`${currentUser.name} is blocked for 5 min`)
                                    errors.push({msg: `${currentUser.name} is blocked for some time. Try again later!`})
                                    setTimeout(() => (blocked.shift()),  5 * 60 * 1000);
                                }   
            
                                errors.push({msg: `Incorrect password. You have ${currentUser.attempts} attempts to log in!`})
            
                                return res.render('auth-pages/login',{
                                    errors,
                                    disabled: disabled,
                                });
                        }
                });
            }
        }
            else{
                errors.push({msg:'User with such name does not exist!'});
                res.render('auth-pages/login',{
                    errors,
                });  
            }
        })
        .catch(err => console.error('Error executing query while finding user', err.stack))
})

//if user does not exist, he can register via register page
router.get('/register', (req, res) => {
    return res.render('auth-pages/register');
})

//if user has a name, but there is no password
let EmptyPasswordOrValidationError = true;
router.get('/register/:name', (req,res) => {
    let errors = [];
    if(EmptyPasswordOrValidationError) errors.push({msg:'You still have not a password, please enter it and confirm'})
    else errors.push({msg: 'Password does not fit requirements! \nYour pass must contain letters and arithmetic signs!'})
    return res.render('auth-pages/register', {
        errors,
        user: currentUser,
        disabled: 'disabled',
    })
})

//Update users password
function updatePassword(user){
    bcrypt.hash(user.registerPassword, 10, (err, hashedPassword) => {
        if(err) throw err;
        console.log(user.registerPassword,hashedPassword);
        
        storeAndUpdatePassword(currentUser.name, user.registerPassword, 'update');

        const query = `UPDATE users
        SET userpass = '${hashedPassword}'
        WHERE _id = ${user.id};`;
    
        pool.query(query)
            .then(() => {console.log('Password was updated!')})
            .catch(err => console.error('Error while updating', err.stack));
    })

}

//Send info about user to server and validate his credentials
router.post('/register', (req,res) => {
    let errors = []; 
    let user = req.body; 
    
    const query = `SELECT * FROM users WHERE username = '${user.registerUsername}';`; 
        pool.query(query)
            .then(result => {
                //check if user exist and also he has not empty password
                if(typeof user.id == 'undefined' && result.rows.length > 0){
                    errors.push({msg: 'Username is already in use!'});
                }
                //check if user confirmed password
                else if(user.registerPassword !== user.confirmPassword)  {
                    errors.push({msg: 'Please confirm you password!'});
                }
                //update his password if password is empty 
                else if(user.id > 0){
                        //check is pass is limited and change it in proper way
                        if(currentUser.passlimit){
                            console.log(validateLimitedPassword(user.registerPassword));
                            if(validateLimitedPassword(user.registerPassword)){
                                EmptyPasswordOrValidationError = true;
                                updatePassword(user); 
                                return res.redirect('/auth');
                            }
                            EmptyPasswordOrValidationError = false;
                        }
                }
                   if(errors.length == 0 && user.id == ''){ 
                    
                    bcrypt.hash(user.registerPassword, 10, (err, hashedPassword) => {
                    if(err) throw err;

                    storeAndUpdatePassword(user.registerUsername, user.registerPassword, 'insert');
    
                    const query = `INSERT INTO users(username, userpass, userblock, passlimit) VALUES ('${user.registerUsername}','${hashedPassword}', false, false);`;

                    pool.query(query)
                        .then(() => {
                            console.log('User data was added to DB')
                            return res.redirect('/auth/')
                        })
                        .catch(err => console.error('Error executing query while adding user', err.stack))
                        })
                    }
                    else{
                        if(user.id){
                            res.redirect(`/auth/register/${currentUser.name}`);
                        }
                        else{
                            res.render('auth-pages/register', {
                                errors,
                            })
                        }
                    }
            })
            .catch(err => console.error('Error executing query while finding user', err.stack))
})

//User logged in and get to page with funcionality
router.get('/main/:username', (req,res) => {
    if(!loggedIn)
        return res.redirect('/auth/');
    
    if(req.params.username === 'ADMIN'){
        return res.render('user/mainPage', {
            name: 'ADMIN',
            access: '',
        });
    }
    else if(currentUser.passlimit)
        if(!validateLimitedPassword(currentUser.pass)){
        return res.render('user/mainPage',{
            name: req.params.username,
            access: 'hidden',
            error: true,
        });
    }
    
    return res.render('user/mainPage', {
            name: req.params.username,
            access: 'hidden',
        })  
})

//if user wants to change password he will be redirected to this page
router.get('/change/:name', (req,res) => {
    return res.render('auth-pages/changePass', {
        user: currentUser,
    })
})

router.post('/change', (req,res) => {
    let user = req.body; 
    let errors = [];

    if(currentUser.pass !== user.oldPassword){
        errors.push({msg:'Old Password is incorrect!'});
    }
    if(user.registerPassword !== user.confirmPassword){
       errors.push({msg: 'Password is no confirmed!'})
    }
    if(currentUser.passlimit){
        if(!validateLimitedPassword(user.registerPassword))
            errors.push({msg: 'Password does not fit requirements!'});
    }
    if(errors.length > 0){
        return res.render('auth-pages/changePass', {
            user: currentUser,
            errors: errors,
        })
    }

    updatePassword(user);
    return res.redirect(`/auth/main/${currentUser.name}`);
})

//ADMIN user will get a list of users, he can update them
//(new username, new pasword, add new user, delete user, block user, passlimit)
router.get('/admin/list', (req,res) => {
    if(currentUser.name !== 'ADMIN'){
        return res.redirect('/auth/');
    }
    const query = `SELECT * FROM users;`;
    let users = [];

    pool.query(query)
        .then(d => {
            users = d.rows.map(el => {
                return el; 
            })
            pool.query('SELECT * FROM "forAdmin";').then(result => {
                result.rows.forEach(el => {
                    users.forEach(e => {
                        if(e.username == el.name){
                            e.userpass = el.password;
                            console.log(e.username,el.password);
                        }
                    })
                })
            })
                .catch(err => console.error(err))
                .finally(() => {
                    users.shift();
                    res.render('admin/list', {
                        users
                    });
                })
        })
        .catch(err => console.error('Error while selecting all users', err.stack))
})

//Users will be deleted by ADMIN
router.get('/admin/delete/:name', (req,res) => {
    const query = `DELETE FROM users WHERE username = '${req.params.name}';`;

    pool.query(query)
        .then(() => {
            console.log('user was deleted');
            storeAndUpdatePassword(req.params.name, '', 'delete');
            return res.redirect('/auth/admin/list');
        })
        .catch(err => {console.error('error while deleting user', err.stack)})
})

//ADMIN will get to this page in order to ADD user 
router.get('/admin/user', (req,res) => {
    res.render('admin/addOrUpdate', {
        viewTitle: 'Add new user',
    });
})

//ADMIN will get to this page in order to UPDATE user
let userToUpdateFromAdmin = {};
router.get('/admin/user/:name', (req,res) => {
    let errors = [];
    const query = `SELECT * FROM users WHERE username = '${req.params.name}';` 
    pool.query(query) 
        .then(result => {
            pool.query(`SELECT * FROM "forAdmin" WHERE name = '${req.params.name}';`)
                .then(forAdmin => {
                    
                    userToUpdateFromAdmin = result.rows[0];
                    userToUpdateFromAdmin.userpass = forAdmin.rows[0].password;
                    
                    res.render('admin/addOrUpdate', {
                        user: userToUpdateFromAdmin,
                        viewTitle: `Update user: ${req.params.name}`,
                        errors
                })
            }).catch(err => console.error(err));
        })
        .catch(err => console.error(err));
})

//Send request to server to UPDATE/CREATE new user
router.post('/admin/user', (req,res) => {
    if(req.body.id !== ''){
        updateUserFromAdmin(req,res);
    }
    else{
        createUserFromAdmin(req,res);
    }
})

//function to update user
async function updateUserFromAdmin(req, res) {
    let userpass = req.body.UserPassword; 
    if(req.body.UserPassword !== ''){
        userpass = await bcrypt.hash(req.body.UserPassword, 10) || '';
    }
    let block = req.body.block || false;
    let limit = req.body.limit || false; 

    let result = await pool.query(`SELECT * FROM users WHERE username='${req.body.UserUsername}';`);

    if(result.rows.length > 0 && userToUpdateFromAdmin.username !== req.body.UserUsername){
        return res.render('admin/addOrUpdate', {
            user: userToUpdateFromAdmin,
            viewTitle: `Update user: ${userToUpdateFromAdmin.username}`,
            errors: [{msg: 'Username should be unique, try again!'}],
        })
    }

    const query = `UPDATE users 
                   SET username = '${req.body.UserUsername}', userpass = '${userpass}', userblock = ${block}, passlimit = ${limit}
                   WHERE _id = ${req.body.id};`;
    pool.query(query)
        .then(() => {
            console.log('User was updated by ADMIN');
            storeAndUpdatePassword(req.body.UserUsername, req.body.UserPassword, 'update');
            return res.redirect('/auth/admin/list');
        })
        .catch(err => console.error(err));
}
//function to create user
async function createUserFromAdmin(req, res) {
    let userpass = req.body.UserPassword; 
    if(req.body.UserPassword !== ''){
        userpass = await bcrypt.hash(req.body.UserPassword, 10) || '';
    }
    console.log(userpass, req.body.UserPassword);
    let block = req.body.block || false;
    let limit = req.body.limit || false; 

    let result = await pool.query(`SELECT * FROM users WHERE username='${req.body.UserUsername}';`);

    if(result.rows.length > 0){
        return res.render('admin/addOrUpdate', {
            viewTitle: 'Add New User',
            errors: [{msg: 'You can add user only with unique name!'}]
        })
    }

    const query = `INSERT INTO users(username, userpass, userblock, passlimit)
     VALUES ('${req.body.UserUsername}', '${userpass}', ${block}, ${limit});`;

    pool.query(query)
        .then(() => {
            console.log('New User added by Admin');
            storeAndUpdatePassword(req.body.UserUsername, req.body.UserPassword, 'insert');
            return res.redirect('/auth/admin/list');
        })
        .catch(err => console.error('Error while adding new user by admin', err.stack))
}

// Logout and redirect to log in page
router.get('/logout', (req,res) => { 
    loggedIn = false; 
    return res.redirect('/auth/');
})

//write data in file locally and redirect to func page
router.get('/file', (req,res) => {
    writeDataInFile('data.txt');
    return res.redirect(`/auth/main/${currentUser.name}`);
})

module.exports = router;
