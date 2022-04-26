// * IMPORTS *
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Configuração do JSON
app.use(express.json())

// Models
const User = require('./models/User')
const { use } = require('express/lib/application')

// Rotas Publicas
app.get('/', (req,res)=>{
    res.status(200).json({msg:"Bem Vindo"})
})

// Rotas Privadas
app.get("/user/:id", checkToken, async (req, res) =>{
    const id = req.param.id
    // Checar login
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg:"Usuario nao encontrado"})
    }

    res.status(200).json({ user })
})

// Verificação do TOKEN
function checkToken(req, res, next){
    
    const authHeader = req.authHeader['authorization']
    const token = authHeader && authHeader.split("")[1]

    if(!token){
        return res.status(401).json({msg: "Acesso Negado"})
    }
    try{
        
        const secret = process.env.SECRET 
        jwt.verify(token, secret)
        next()

    }catch{
        res.status(400).json({msg:"Token Invalido"})
    }
}

// Registro de Usuario
app.post('/auth/register', async(req,res) =>{

    const {name, email, password, confirmpassword} = req.body

    // Verificação de Campos de Cadastro
    if(!name){
        return res.status(422).json({msg:'Nome Obrigatorio' })
    }
    if(!email){
        return res.status(422).json({msg:'Email Obrigatorio' })
    }
    if(!password){
        return res.status(422).json({msg:'Senha Obrigatorio' })
    }
    if(password !== confirmpassword){
        return res.status(422).json({msg:'As senhas nao conferem!'})
    }
    // Verificação de Usuario ja existente
    const userExists = await User.findOne({email: email})
    if(userExists){
        return res.status(422).json({msg:'Email ja cadastrado!'})
    }
    
    // Criar senha *HASH*
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Criar Usuario
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try{

        await user.save()
        res.status(201).json({msg:'Usuario criado com sucesso'})

    }catch(error){
        console.log(error)
        res.status(500).json({msg: 'error'})
    }
})

// Login de Usuario
app.post("/auth/login", async (req,res) =>{
    const { email, password } = req.body
    // Validação
    if(!email){
        return res.status(422).json({msg:'Email Obrigatorio' })
    }
    if(!password){
        return res.status(422).json({msg:'Senha Obrigatorio' })
    }
    // Checar se o Usuario Existe
    const user = await User.findOne({email: email})
    if(!user){
        return res.status(404).json({msg:'Usuario nao encontrado!'})
    }
    // Checar senha do Usuario
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg:'Senha Invalida!'})
    }
    try{

        const secret = process.env.secret
        const token = jwt.sign({
            id: user._id
        }, 
        secret,
        )
        res.status(200).json({msg: "Login feito com Sucesso!", token})

    }catch(err){
        console.log(error)
        res.status(500).json({msg: 'error'})
    }
})

// Credencial da DB
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

// Conexao com a  DB
mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.xgql1.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`,
    )
    .then(() => {
        app.listen(8080)
        console.log('DB Conectada')
    })
    .catch((err) => console.log(err))
     


