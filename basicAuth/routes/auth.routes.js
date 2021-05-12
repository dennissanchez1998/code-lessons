const {
    Router
} = require('express')
const router = new Router()
const bcryptjs = require('bcryptjs')
const saltRounds = 10 // SALTING
const User = require('../models/User.model')
const {
    mongoose
} = require('mongoose')
// GET Display the signup form
router.get('/signup', (req, res) => {
    res.render('auth/signup')
})
// POST Process from data
router.post('/signup', (req, res, next) => {
    console.log('The form data:', req.body)
    const {
        username,
        email,
        password
    } = req.body

    if (!username || !email || !password) {
        res.render('auth/signup', {
            error: "todos los campos son obligatorios compa"
        })
        return;
    }

    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;



    if (!regex.test(password)) {
        res
            .status(500)
            .render('auth/signup', {
                errorMessage: 'ah no vale eso es lo que se te ocurrio mariquito.'
            });
        return;
    }






    // OPCIÓN A - PROCESO SÍNCRONO
    // const hashedPassword = bcryptjs.hashSync(password, 10);
    // console.log(`Password hash: ${hashedPassword}`);
    // OPCIÓN B - PROCESO ASÍNCRONO
    // PROCESO DE ENCRIPTAMIENTO
    bcryptjs
        // REVOLVENTE
        .genSalt(saltRounds)
        // HASHING (SINTESIS DEL PASSWORD A UN STRING CHIQUITO PARA BASE DE DATOS)
        .then(salt => bcryptjs.hash(password, salt))
        // INSERCIÓN EN BASE DE DATOS
        .then(hashedPassword => {
            console.log(`Password hash:: ${hashedPassword}`)
            return User.create({
                username,
                email,
                passwordHash: hashedPassword
            })
        })
        .then(userFromDB => {
            console.log("Usuario creado:", userFromDB)
            res.redirect('/userProfile')
        })
        .catch(e => {
            if (e instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', {
                    error: e.message
                })


            } else if (e.code === 11000) {
                res.status(500).render('auth/signup', {
                    error: "qlq loco te estan vacilando"
                })

            }
        })
})
// GET Profile Page
router.get('/userProfile', (req, res) => {

    res.render('users/user-profile', {
        userInSession: req.session.currentUser
    });
})




router.get('/login', (req, res) => {
    res.render('auth/login');
})
router.post('/login', (req, res, next) => {
    console.log('SESSION', req.session);









    // 1. OBTENER LOS DATOS DEL FORMULARIO
    const {
        email,
        password
    } = req.body
    if (email === "" || password === "") {
        res.render('auth/login', {
            errorMessage: "Falta un campo por llenar"
        })
        return
    }
    // 2. ENCONTRAR AL USUARIO DENTRO DE LA BASE DE DATOS A TRAVÉS DEL EMAIL
    User.findOne({
            email
        })
        .then((usuario) => {
            // a. VALIDACIÓN - Si el usuario no fue encontrado en DB
            if (!usuario) {
                res.render('auth/login', {
                    errorMessage: "El correo no está registrado. Intenta con otro mail. O regístrate."
                })
                return
            } else if (bcryptjs.compareSync(password, usuario.passwordHash)) { // Si todo bien, vamos a verificar su password. Si esto sucede un true...
                console.log(usuario)

                req.session.currentUser = usuario

                res.render('users/userProfile', {
                    user: usuario
                })
            } else {
                res.render('auth/login', {
                    errorMessage: 'Password Incorrecto'
                })
            }
        })
        .catch(e => next(e))
})

module.exports = router