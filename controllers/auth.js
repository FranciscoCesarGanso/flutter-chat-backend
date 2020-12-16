const { response, request } = require("express");
const { validationResult } = require("express-validator");
const Usuario = require('../models/usuario');
const bcrypt= require("bcryptjs");
const { generarJWT } = require("../helpers/jwt");
const usuario = require("../models/usuario");
const crearUsuario = async (req,res=response) => {
    const{email,password}=req.body;
    try{
        const exiteEmail = await Usuario.findOne({
            email:email
        });
        if(exiteEmail){
            return res.status(400).json({
                ok:false,
                msg:'Credenciales no validas'
            });
        }
        const usuario = new Usuario(req.body);
        //encriptar contraseña
        const salt= bcrypt.genSaltSync();
        usuario.password=bcrypt.hashSync(password,salt);
        await usuario.save();
        const token =await generarJWT(usuario.id);
        res.json({
            ok:true,
            usuario,
            token
        });
    }
    catch(error){
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'hable con el admin'
        })
    }
}
const login= async(req,res=response) => {
    const {email,password } = req.body;
    try{
        const usuarioDB=await usuario.findOne({email});
        if(!usuarioDB){
            return res.status(404).json({
                ok:false,
                msg:'Email no encontrado'
            });
        }
        const validPassword = bcrypt.compareSync(password,usuarioDB.password);
        if(!validPassword){
            return res.status(404).json({
                ok:false,
                msg:'Contraseña no valida'
            });
        }
        //Generar JWT
        const token =await generarJWT(usuarioDB.id);
        res.json({
            ok:true,
            usuarioDB,
            token
        });
        
    }
    catch(error){
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'hable con el admin'
        })
    }
}
const renewToken = async(req,res=response) =>{
    const{uid}= req.uid;
    try{
        const token =await generarJWT(uid);
        const usuarioDB =await Usuario.findById(uid);
        res.json({
            ok:true,
            usuario:usuarioDB,
            token
        });
    }
    catch(error){
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'hable con el admin'
        })
    }
}    
module.exports={
    crearUsuario,
    login,
    renewToken
};    