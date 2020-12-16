/*
//path
api/login
*/
const{Router}=require('express');
const { check } = require('express-validator');
const { crearUsuario,login,renewToken } = require('../controllers/auth');
const { validarCampos } = require('../middlewares/validar-campos');
const { validarJWT } = require('../middlewares/validar-jwt');
const router=Router();
//ruta,middlewares y controlador
router.post('/new',[
    check('nombre','El nombre es obligatorio').not().isEmpty(),
    check('password','La constraseña es obligatoria').not().isEmpty(),
    check("email","El email es obligatorio").not().isEmpty(),
    check('email',"Tiene que cumplit las caracteristicas de un email").isEmail(),
    validarCampos
],crearUsuario);

router.post('/',[
    check('password','La constraseña es obligatoria').not().isEmpty(),
    check("email","El email es obligatorio").not().isEmpty(),
    check('email',"Tiene que cumplit las caracteristicas de un email").isEmail(),
    validarCampos
],login);
router.get('/renew',validarJWT,renewToken);
module.exports=router; 