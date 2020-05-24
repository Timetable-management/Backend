const express = require('express');
const chalk = require('chalk');
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt'); //Para encriptar contraseñas

//Middleware para no tener problemas con CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Allow-Request-Method');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.header('Allow', 'GET, POST, OPTIONS, PUT, DELETE');
    next();
});

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

//Declaramos puerto y empezamos la escucha
const PORT = process.env.PORT || 5555;
app.listen(PORT, () => {
    console.log(chalk.green.inverse.bold(`Conectado con puerto ${PORT}`))
});

//Conectamos con la BBDD y ocultamos contraseñas etc
require('dotenv').config();
const dataBase = require('./conf');

//Ruta GET para Homepage
app.get('/', (req, res) => {
    res.send('Estoy en Homepage')
})

// -------------------------LOGIN---------------------------------------

//Hacemos Login: Localizamos al usuario por el email y verificamos que la contraseña coincide con la guardada
app.post('/login', (req, res) => {
    dataBase.query('SELECT * FROM empleados WHERE correo = ?', req.body.correo, async (error, results) => {
        if (error) {
            res.send(error);
        } else {
            if (results.length !== 0) {
                if (await bcrypt.compare(req.body.contraseña, results[0].contraseña)) {
                    res.send(results);
                } else {
                    res.send([{msg: 'Te has equivocado de contraseña'}]);
                }
            } else {
                res.send([{msg: 'No estás registrado'}]);
            }
        }
    })
})

// -------------------------FIN LOGIN-----------------------------------

// -------------------------REGISTRO------------------------------------

//Ruta POST para nuevo empleado encriptando contraseña
app.post('/signIn', async (req, res) => {
    let registerResponse = {
        usuario: '',
        errors: []
    };
    const hashedPassword = await bcrypt.hash(req.body.contraseña, 10);
    const nombre = req.body.nombre;
    const primerApellido = req.body.primerApellido;
    const segundoApellido = req.body.segundoApellido;
    const correo = req.body.correo.toLowerCase();
    const cargo = req.body.cargo;


    dataBase.query('SELECT correo FROM empleados WHERE correo = ?', req.body.correo, (error, results) => {
        if (error) {
            res.send(error)
        } else {
            if (req.body.repeatPassword !== req.body.contraseña) {
                registerResponse.errors.push({
                    msg: 'Las contraseñas no son iguales'
                });
            }
            if (req.body.repeatPassword.length < 6 || req.body.contraseña.length < 6) {
                registerResponse.errors.push({
                    msg: 'La contraseña debe tener al menos 7 caracteres'
                });
            }
            if (!nombre || !primerApellido || !segundoApellido || !correo || !cargo) {
                registerResponse.errors.push({
                    msg: 'Rellena todos los campos'
                });
            }
            if (!correo.includes('@')) {
                registerResponse.errors.push({
                    msg: 'Email incorrecto'
                });
            }
            if (results.length !== 0) {
                registerResponse.errors.push({
                    msg: 'Este correo ya esta registrado'
                })
            }
            if (registerResponse.errors.length > 0) {
                res.send(registerResponse);
            } else {
                const user = {
                    nombre: req.body.nombre,
                    primerApellido: req.body.primerApellido,
                    segundoApellido: req.body.segundoApellido,
                    correo: req.body.correo,
                    cargo: req.body.cargo,
                    contraseña: hashedPassword
                }
                dataBase.query('INSERT INTO empleados SET ?', user, (error, results) => {
                    if (error) {
                        res.send(error);
                    } else {
                        dataBase.query('SELECT * FROM empleados WHERE correo = ?', req.body.correo, (error, results) => {
                            !error ? res.send(results) : res.send(error)
                        })
                    }
                })
            }
        }
    })
})

// -------------------------FIN REGISTRO--------------------------------

// -------------------------HOME GESTOR/ADMINISTRADOR-------------------

//GESTOR --> Ruta GET para TODOS los Empleados
app.get('/employee', (req, res) => {
    dataBase.query('SELECT * FROM empleados', (error, results) => {
        if (error) {
            res.send(error);
        } else {
            res.send(results);
        }
    })
})

//GESTOR --> Ruta DELETE para empleados por correo
app.delete('/employee/:correo', (req, res) => {
    dataBase.query('DELETE  FROM empleados WHERE correo = ?', req.params.correo, (error, results) => {
        if (error) {
            res.send(error);
        } else {
            res.redirect('/employee');
        }
    })
})

// -------------------------FIN HOME GESTOR/ADMINISTRADOR-----------------
// -------------------------USUARIO---------------------------------------

// -------------------------FIN USUARIO-----------------------------------

