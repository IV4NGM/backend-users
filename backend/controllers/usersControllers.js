const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
const asyncHandler = require('express-async-handler')

// Importar servicios de email
const sendEmail = require('@/utils/email')

const User = require('@/models/usersModel')
const VerifyUserToken = require('@/models/verifyUserTokenModel')
const ResetPasswordToken = require('@/models/resetPasswordTokenModel')

const createUser = asyncHandler(async (req, res) => {
  const { name, email, password, isAdmin } = req.body

  // Verificar si se pasan todos los datos
  if (!name || !email || !password) {
    res.status(400)
    throw new Error('Debes ingresar todos los campos')
  }
  // Establecer la propiedad isAdmin
  const admin = !(!isAdmin || isAdmin !== 'true')
  // Hacer el Hash al password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  let userRegistered

  // Verificar que el email no esté registrado
  const userExists = await User.findOne({ email })
  if (userExists) {
    if (userExists.isActive) {
      res.status(400)
      throw new Error('El email ya está registrado en la base de datos')
    } else {
      userRegistered = await User.findByIdAndUpdate(userExists.id, {
        name,
        email,
        password: hashedPassword,
        isVerified: false,
        isAdmin: admin,
        isActive: true,
        tokenVersion: userExists.tokenVersion + 1
      }, { new: true })

      if (!userRegistered) {
        res.status(400)
        throw new Error('No se pudieron guardar los datos')
      }
    }
  } else {
    // Crear el usuario
    userRegistered = await User.create({
      name,
      email,
      password: hashedPassword,
      isAdmin: admin
    })

    if (!userRegistered) {
      res.status(400)
      throw new Error('No se pudieron guardar los datos')
    }
  }
  if (userRegistered) {
    // Enviar email de verificación

    // Eliminar los tokens si es que hay
    await VerifyUserToken.deleteMany({ user: userRegistered })

    // Crear token aleatorio y enviarlo al email
    const verificationToken = crypto.randomBytes(16).toString('hex')

    const salt = await bcrypt.genSalt(10)
    const hashedToken = await bcrypt.hash(verificationToken, salt)

    await VerifyUserToken.create({
      user: userRegistered,
      token: hashedToken
    })

    const isEmailSent = await sendEmail(userRegistered.email, 'verifyEmail', {
      name: userRegistered.name,
      link: process.env.EMAIL_BASE_URL + `/verify/${userRegistered._id}/${verificationToken}`
    })

    res.status(201).json({
      _id: userRegistered.id,
      name: userRegistered.name,
      email: userRegistered.email,
      isVerified: userRegistered.isVerified,
      isAdmin: userRegistered.isAdmin,
      isVerificationEmailSent: isEmailSent
    })
  }
})

const generateToken = (userId, tokenVersion) => {
  return jwt.sign({ user_id: userId, token_version: tokenVersion }, process.env.JWT_SECRET, {
    expiresIn: '30d'
  })
}

const sendVerificationEmail = asyncHandler(async (req, res) => {
  const { email } = req.body
  if (!email) {
    res.status(400)
    throw new Error('Debes ingresar el email')
  }
  const user = await User.findOne({ email })
  if (!user || !user.isActive) {
    res.status(400)
    throw new Error('No existe el usuario en la base de datos')
  }
  if (user.isVerified) {
    res.status(400)
    throw new Error('El usuario ya se encuentra verificado')
  }
  // Enviar email de verificación

  // Eliminar los tokens si es que hay
  await VerifyUserToken.deleteMany({ user })

  // Crear token aleatorio y enviarlo al email
  const verificationToken = crypto.randomBytes(16).toString('hex')

  const salt = await bcrypt.genSalt(10)
  const hashedToken = await bcrypt.hash(verificationToken, salt)

  await VerifyUserToken.create({
    user,
    token: hashedToken
  })

  const isEmailSent = await sendEmail(user.email, 'verifyEmail', {
    name: user.name,
    link: process.env.EMAIL_BASE_URL + `/verify/${user._id}/${verificationToken}`
  })

  if (isEmailSent) {
    res.status(200).json({ message: 'Se ha enviado el email' })
  } else {
    res.status(400)
    throw new Error('No se pudo enviar el email')
  }
})

const verifyUser = asyncHandler(async (req, res) => {
  const { id, token } = req.body

  if (!id || !token) {
    res.status(400)
    throw new Error('Debes ingresar todos los campos')
  }

  try {
    const user = await User.findById(id)

    if (!user || !user.isActive) {
      res.status(400)
      throw new Error('Token inválido')
    }
    if (user && user.isVerified) {
      res.status(400)
      throw new Error('El usuario ya está verificado')
    }

    const userToken = await VerifyUserToken.findOne({ user: id })
    if (!userToken || userToken.expiresAt < new Date() || !await bcrypt.compare(token, userToken.token)) {
      res.status(400)
      throw new Error('Token expirado o inválido')
    }
    const userUpdated = await User.findOneAndUpdate(user, {
      isVerified: true
    }, { new: true })
    if (userUpdated) {
      await VerifyUserToken.deleteMany({ user })
      res.status(200).json({
        _id: userUpdated.id,
        name: userUpdated.name,
        email: userUpdated.email,
        isVerified: userUpdated.isVerified,
        isAdmin: userUpdated.isAdmin
      })
    } else {
      res.status(400)
      throw new Error('No se pudo verificar el usuario')
    }
  } catch (error) {
    if (error.name === 'CastError' && error.kind === 'ObjectId') {
      res.status(404)
      throw new Error('El usuario no se encuentra en la base de datos')
    } else {
      res.status(res.statusCode || 400)
      throw new Error(error.message || 'No se pudo verificar el usuario')
    }
  }
})

const sendResetEmail = asyncHandler(async (req, res) => {
  const { email } = req.body
  if (!email) {
    res.status(400)
    throw new Error('Debes ingresar el email')
  }
  const user = await User.findOne({ email })
  if (!user || !user.isActive) {
    res.status(400)
    throw new Error('No existe el usuario en la base de datos')
  }

  // Enviar email de reset password

  // Eliminar los tokens si es que hay
  await ResetPasswordToken.deleteMany({ user })

  // Crear token aleatorio y enviarlo al email
  const resetToken = crypto.randomBytes(16).toString('hex')

  const salt = await bcrypt.genSalt(10)
  const hashedToken = await bcrypt.hash(resetToken, salt)

  const isEmailSent = await sendEmail(user.email, 'resetPassword', {
    name: user.name,
    link: process.env.EMAIL_BASE_URL + `/reset-password/${user._id}/${resetToken}`
  })

  await ResetPasswordToken.create({
    user,
    token: hashedToken
  })

  if (isEmailSent) {
    res.status(200).json({ message: 'Se ha enviado el email' })
  } else {
    res.status(400)
    throw new Error('No se pudo enviar el email')
  }
})

const resetPassword = asyncHandler(async (req, res) => {
  const { id, token, password } = req.body

  if (!id || !token || !password) {
    res.status(400)
    throw new Error('Debes ingresar todos los campos')
  }

  try {
    const user = await User.findById(id)

    if (!user || !user.isActive) {
      res.status(400)
      throw new Error('Token inválido')
    }

    const userToken = await ResetPasswordToken.findOne({ user: id })

    if (!userToken || userToken.expiresAt < new Date() || !await bcrypt.compare(token, userToken.token)) {
      res.status(400)
      throw new Error('Token expirado o inválido')
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const userUpdated = await User.findOneAndUpdate(user, {
      password: hashedPassword,
      tokenVersion: user.tokenVersion + 1
    }, { new: true })
    if (userUpdated) {
      await sendEmail(user.email, 'resetPasswordConfirmation', {
        name: user.name
      })
      await ResetPasswordToken.deleteMany({ user })
      res.status(200).json({
        _id: userUpdated.id,
        name: userUpdated.name,
        email: userUpdated.email,
        isVerified: userUpdated.isVerified,
        isAdmin: userUpdated.isAdmin
      })
    } else {
      res.status(400)
      throw new Error('No se pudo actualizar la contraseña')
    }
  } catch (error) {
    if (error.name === 'CastError' && error.kind === 'ObjectId') {
      res.status(404)
      throw new Error('El usuario no se encuentra en la base de datos')
    } else {
      res.status(res.statusCode || 400)
      throw new Error(error.message || 'No se pudo actualizar la contraseña')
    }
  }
})

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    res.status(400)
    throw new Error('Debes ingresar todos los campos')
  }

  // Verificamos si el usuario existe y también su password
  const user = await User.findOne({ email })
  if (user && user.isActive && (await bcrypt.compare(password, user.password))) {
    // Generamos un token si y solo si el usuario está verificado
    if (user.isVerified) {
      res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
        isAdmin: user.isAdmin,
        token: generateToken(user.id, user.tokenVersion)
      })
    } else {
      res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
        isAdmin: user.isAdmin
      })
    }
  } else {
    res.status(400)
    throw new Error('Credenciales incorrectas')
  }
})

const getUser = asyncHandler(async (req, res) => {
  const user = req.user.toObject()
  delete user.isActive
  delete user.tokenVersion
  res.status(200).json(user)
})

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find({ isActive: true }).select('-password -isActive -tokenVersion')
  if (users) {
    res.status(200).json(users)
  } else {
    res.status(400)
    throw new Error('No se puede mostrar la información en este momento')
  }
})

const updateUser = asyncHandler(async (req, res) => {
  const { name, password, isAdmin, logout } = req.body
  if (!name && !password && !isAdmin) {
    res.status(400)
    throw new Error('Debes enviar al menos un campo a actualizar')
  }
  if (name === '') {
    res.status(400)
    throw new Error('El nombre no debe ser vacío')
  }
  let newIsAdmin = req.user.isAdmin
  if (isAdmin) {
    if (isAdmin === 'true') {
      newIsAdmin = true
    } else if (isAdmin === 'false') {
      newIsAdmin = false
    } else {
      res.status(400)
      throw new Error('El campo isAdmin no es válido')
    }
  }
  let newPassword
  if (password) {
    // Hacer el Hash al password
    const salt = await bcrypt.genSalt(10)
    newPassword = await bcrypt.hash(password, salt)
  }
  const newTokenVersion = logout === 'false' ? req.user.tokenVersion : req.user.tokenVersion + 1
  if (newPassword) {
    const userUpdated = await User.findByIdAndUpdate(req.user.id, {
      name,
      password: newPassword,
      isAdmin: newIsAdmin,
      tokenVersion: newTokenVersion
    }, { new: true })
    if (userUpdated) {
      res.status(200).json({
        _id: userUpdated.id,
        name: userUpdated.name,
        email: userUpdated.email,
        isAdmin: userUpdated.isAdmin
      })
    } else {
      res.status(400)
      throw new Error('No se pudieron guardar los datos')
    }
  } else {
    const userUpdated = await User.findByIdAndUpdate(req.user.id, {
      name,
      isAdmin: newIsAdmin
    }, { new: true })
    if (userUpdated) {
      res.status(200).json({
        _id: userUpdated.id,
        name: userUpdated.name,
        email: userUpdated.email,
        isAdmin: userUpdated.isAdmin
      })
    } else {
      res.status(400)
      throw new Error('No se pudieron guardar los datos')
    }
  }
})

const deleteUser = asyncHandler(async (req, res) => {
  const userDeleted = await User.findByIdAndUpdate(req.user.id, {
    isActive: false,
    tokenVersion: req.user.tokenVersion + 1
  },
  { new: true })
  if (userDeleted) {
    res.status(200).json({ message: 'Usuario eliminado exitosamente' })
  } else {
    res.status(400)
    throw new Error('No se ha podido eliminar el usuario')
  }
})

module.exports = {
  createUser,
  sendVerificationEmail,
  verifyUser,
  sendResetEmail,
  resetPassword,
  loginUser,
  getUser,
  getAllUsers,
  updateUser,
  deleteUser
}
