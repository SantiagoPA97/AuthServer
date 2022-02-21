const { response } = require('express');
const Usuario = require('../models/Usuario');
const bcrypt =  require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');
const { db } = require('../models/Usuario');

const crearUsuario = async (req, res) => {
    const { email, name, password } = req.body;

    try {
        
        //Verificar correo unico
        const usuario = await Usuario.findOne({ email }); 

        if (usuario) {
            return res.status(400).json({
                ok: false,
                msg: 'Usuario ya existe'
            });
        }

        //Crear usuario con modelo
        const dbUser = new Usuario(req.body);

        //Encriptar(hash) contraseña
        const salt = bcrypt.genSaltSync(10);
        dbUser.password = bcrypt.hashSync(password, salt);
    
        //Generar el JWT
        const token = await generarJWT(dbUser._id, name);

        //Crear usuario BD
        await dbUser.save();
    
        //Generar respuesta exitosa
        return res.status(201).json({
            ok: true,
            uid: dbUser._id,
            name,
            email,
            token
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Por favor hable con el administrador'
        });
    }
}

const loginUsuario = async (req, res) => {
    const { email, password } = req.body;

    try {

        const dbUser = await Usuario.findOne({ email });
        if (!dbUser) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }

        //Confirmar si la contraseña hace match
        const validPassword = bcrypt.compareSync(password, dbUser.password);
        if (!validPassword) {
            return res.status(400).json({
                ok: false,
                msg: 'La contraseña no es valida'
            });
        }

        //Generar el JWT
        const token = await generarJWT(dbUser._id, dbUser.name);

        //Respuesta del servicio
        return res.json({
            ok: true,
            uid: dbUser._id,
            name: dbUser.name,
            email,
            token
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Hable con el admin'
        });
    }
}

const revalidarToken = async (req, res) => {

    const { uid } = req;

    //Leer base de datos
    const dbUser = await Usuario.findById(uid);

    //Generar el JWT
    const token = await generarJWT(uid, dbUser.name);

    return res.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    });

}

module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}