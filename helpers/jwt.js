const jwt= require('jsonwebtoken');
const generarJWT = (uid) =>{

    return new Promise((resolve,reject )=>{
        const payload ={uid};
        jwt.sign(payload,process.env.JWT_KEY,{
            expiresIn:'24h'
        },(err,token) => {
            if(err){
                //no se puedo crear token
                print(err)
                reject('No se pude generar JWT')
            }
            else{
                //tengo token
                resolve(token)
            }
        })
    });
}
module.exports={
    generarJWT
}