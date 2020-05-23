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
    dataBase.query('SELECT * FROM empleados', async (error, results) => {
        if (error) {
            res.send(error);
        } else {
            const thisUser = results.find((empleado) => {
                return empleado.correo === req.body.correo;
            })
            if (thisUser == null) {
                res.send('No estás regitrado');
            } else {
                if (await bcrypt.compare(req.body.contraseña, thisUser.contraseña)) {
                    res.send('La contraseña es igual');
                } else {
                    res.send('Te has equivocado de contraseña');
                }
            }
        }
    })
})

// -------------------------FIN LOGIN-----------------------------------

// -------------------------REGISTRO------------------------------------

//Ruta POST para nuevo empleado encriptando contraseña
app.post('/signIn', async (req, res) => {
    let errorsArray = [];
    const hashedPassword = await bcrypt.hash(req.body.contraseña, 10);
    const nombre = req.body.nombre;
    const primerApellido = req.body.primerApellido;
    const segundoApellido = req.body.segundoApellido;
    const correo = req.body.correo;
    const cargo = req.body.cargo;
    const contraseña = hashedPassword;
    
    if (req.body.repeatPassword !== req.body.contraseña) {
        errorsArray.push({
            msg: 'Las contraseñas no son iguales'
        });
        console.log(errorsArray)
    }
    if (!nombre || !primerApellido || !segundoApellido || !correo || !cargo) {
        errorsArray.push({
            msg: 'nombre vacio'
        });
        console.log(errorsArray)
    }
    if (errorsArray.length > 0) {
        res.send(errorsArray);
        console.log(errorsArray)
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