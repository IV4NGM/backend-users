// Para configurar email
const hbs = require('nodemailer-express-handlebars')
const nodemailer = require('nodemailer')
const path = require('path')

const transporter = nodemailer.createTransport(
  {
    service: process.env.EMAIL_SERVICE,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  }
)

const handlebarOptions = {
  viewEngine: {
    partialsDir: path.resolve('backend/views/'),
    defaultLayout: false
  },
  viewPath: path.resolve('backend/views/')
}

transporter.use('compile', hbs(handlebarOptions))

const sendEmail = async (email, template, context) => {
  let subject = 'Notification from ivangmsystems'
  if (template === 'verifyEmail') {
    subject = 'Verify your account'
  }
  if (template === 'resetPassword') {
    subject = 'Reset your password'
  }
  if (template === 'resetPasswordConfirmation') {
    subject = 'Password reseted successfully'
  }
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      template,
      to: email,
      subject,
      context
    }
    await transporter.sendMail(mailOptions)
    return true
  } catch (error) {
    console.log(error)
    return false
  }
}

module.exports = sendEmail
